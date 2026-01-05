//! DeMoD Game Server Network - Game Selector with DCF Integration
//!
//! Orchestrates game servers with:
//!   - DCF-ID authentication verification
//!   - Balance/quota checks before server start
//!   - Traffic meter session registration
//!   - Usage tracking integration
//!
//! Copyright (c) 2025 DeMoD LLC - All Rights Reserved

use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use bollard::{
    container::{Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions},
    Docker,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info};

// ============================================================================
// CONFIGURATION
// ============================================================================
#[derive(Clone)]
struct AppConfig {
    max_active_servers: usize,
    server_timeout_seconds: u64,
    dcf_id_url: String,
    dcf_internal_key: String,
    meter_url: String,
    min_balance_to_start: f64,
    public_host: String,
}

impl AppConfig {
    fn from_env() -> Self {
        Self {
            max_active_servers: std::env::var("MAX_ACTIVE_SERVERS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(2),
            server_timeout_seconds: std::env::var("SERVER_TIMEOUT_SECONDS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(3600),
            dcf_id_url: std::env::var("DCF_ID_URL")
                .unwrap_or_else(|_| "http://dcf-id:4000".into()),
            dcf_internal_key: std::env::var("DCF_ID_INTERNAL_KEY").unwrap_or_default(),
            meter_url: std::env::var("METER_URL")
                .unwrap_or_else(|_| "http://gsn-meter:9000".into()),
            min_balance_to_start: std::env::var("MIN_BALANCE_TO_START")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(0.0),
            public_host: std::env::var("PUBLIC_HOST")
                .unwrap_or_else(|_| "dcf.demod.ltd".into()),
        }
    }
}

// ============================================================================
// STATE
// ============================================================================
const FREE_TIER_BYTES: i64 = 134_217_728; // 128 MB

#[derive(Clone, Serialize)]
struct ServerState {
    id: u8,
    name: String,
    status: ServerStatus,
    game: Option<String>,
    game_image: Option<String>,
    players: u32,
    max_players: u32,
    started_at: Option<u64>,
    started_by: Option<String>,
    connect_info: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ServerStatus {
    Running,
    Stopped,
    Starting,
    Stopping,
}

#[derive(Clone, Serialize, Deserialize)]
struct GameConfig {
    id: String,
    name: String,
    description: String,
    image: String,
    ports: Vec<String>,
    env: HashMap<String, String>,
    memory_limit: String,
    cpu_limit: String,
}

struct AppState {
    config: AppConfig,
    docker: Docker,
    http_client: reqwest::Client,
    servers: RwLock<HashMap<u8, ServerState>>,
    games: RwLock<HashMap<String, GameConfig>>,
}

// ============================================================================
// DCF-ID INTEGRATION
// ============================================================================
#[derive(Deserialize)]
struct DcfUser {
    username: String,
    access_token: String,
    discord_id: Option<String>,
    data_used: i64,
    account_balance: f64,
    is_vip: bool,
}

#[derive(Deserialize)]
struct DcfApiResponse<T> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

impl AppState {
    async fn verify_dcf_token(&self, token: &str) -> Result<DcfUser, String> {
        let resp = self.http_client
            .get(format!("{}/api/user/verify", self.config.dcf_id_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("X-Internal-Key", &self.config.dcf_internal_key)
            .send()
            .await
            .map_err(|e| format!("DCF-ID request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err("Invalid or expired token".into());
        }

        let api_resp: DcfApiResponse<DcfUser> = resp.json().await
            .map_err(|e| format!("Invalid response: {}", e))?;

        api_resp.data.ok_or_else(|| "User not found".into())
    }

    async fn lookup_by_discord(&self, discord_id: &str) -> Result<DcfUser, String> {
        let resp = self.http_client
            .get(format!("{}/api/user/discord/{}", self.config.dcf_id_url, discord_id))
            .header("X-Internal-Key", &self.config.dcf_internal_key)
            .send()
            .await
            .map_err(|e| format!("DCF-ID request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err("Discord account not linked".into());
        }

        let api_resp: DcfApiResponse<DcfUser> = resp.json().await
            .map_err(|e| format!("Invalid response: {}", e))?;

        api_resp.data.ok_or_else(|| "User not found".into())
    }

    fn can_use_bandwidth(&self, user: &DcfUser) -> bool {
        if user.is_vip {
            return true;
        }
        let free_remaining = FREE_TIER_BYTES - user.data_used;
        free_remaining > 0 || user.account_balance > 0.0
    }

    async fn register_meter_session(
        &self,
        user: &DcfUser,
        server_id: u8,
        client_addr: &str,
    ) -> Result<(), String> {
        let body = serde_json::json!({
            "access_token": user.access_token,
            "discord_id": user.discord_id,
            "username": user.username,
            "server_id": server_id,
            "client_addr": client_addr,
        });

        let resp = self.http_client
            .post(format!("{}/sessions/register", self.config.meter_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Meter registration failed: {}", e))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err("Failed to register metering session".into())
        }
    }
}

// ============================================================================
// API TYPES
// ============================================================================
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self { success: true, message: None, data: Some(data) }
    }
    fn error(msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse { success: false, message: Some(msg.into()), data: None }
    }
}

#[derive(Deserialize)]
struct StartRequest {
    started_by: Option<String>,
    discord_id: Option<String>,
}

#[derive(Deserialize)]
struct LoadGameRequest {
    game: String,
    loaded_by: Option<String>,
}

#[derive(Serialize)]
struct StatsResponse {
    total_users: u32,
    active_servers: u32,
    total_bandwidth_today: u64,
    total_bandwidth_month: u64,
}

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================
fn extract_token(headers: &HeaderMap) -> Option<String> {
    headers.get("X-DCF-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            headers.get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        })
}

// ============================================================================
// HANDLERS
// ============================================================================
async fn health() -> &'static str { "OK" }

async fn list_servers(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<ServerState>>> {
    let servers = state.servers.read().await;
    let mut list: Vec<_> = servers.values().cloned().collect();
    list.sort_by_key(|s| s.id);
    Json(ApiResponse::success(list))
}

async fn get_server(
    Path(id): Path<u8>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<ServerState>>, StatusCode> {
    let servers = state.servers.read().await;
    match servers.get(&id) {
        Some(s) => Ok(Json(ApiResponse::success(s.clone()))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn start_server(
    Path(id): Path<u8>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Validate server ID
    if id < 1 || id > 2 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("Invalid server ID"))));
    }

    // Authenticate user
    let user = if let Some(token) = extract_token(&headers) {
        state.verify_dcf_token(&token).await
    } else if let Some(discord_id) = &req.discord_id {
        state.lookup_by_discord(discord_id).await
    } else {
        Err("Authentication required".into())
    };

    let user = match user {
        Ok(u) => u,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error(e)))),
    };

    // Check bandwidth quota
    if !state.can_use_bandwidth(&user) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            Json(ApiResponse::<()>::error("No bandwidth available. Please add credits.")),
        ));
    }

    // Check balance requirement
    if !user.is_vip && user.account_balance < state.config.min_balance_to_start {
        let free_remaining = FREE_TIER_BYTES - user.data_used;
        if free_remaining <= 0 {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                Json(ApiResponse::<()>::error(format!(
                    "Minimum balance of ${:.2} required",
                    state.config.min_balance_to_start
                ))),
            ));
        }
    }

    // Check server state
    {
        let servers = state.servers.read().await;
        if let Some(server) = servers.get(&id) {
            if server.status == ServerStatus::Running || server.status == ServerStatus::Starting {
                return Err((StatusCode::CONFLICT, Json(ApiResponse::<()>::error("Server already running"))));
            }
        }

        let active = servers.values()
            .filter(|s| s.status == ServerStatus::Running || s.status == ServerStatus::Starting)
            .count();
        if active >= state.config.max_active_servers {
            return Err((StatusCode::TOO_MANY_REQUESTS, Json(ApiResponse::<()>::error("Max servers reached"))));
        }
    }

    // Update state
    {
        let mut servers = state.servers.write().await;
        if let Some(server) = servers.get_mut(&id) {
            server.status = ServerStatus::Starting;
            server.started_by = Some(user.username.clone());
        }
    }

    // Start container
    let container_name = format!("gsn-server-{}", id);
    info!("Starting {} for user {}", container_name, user.username);

    match state.docker.start_container(&container_name, None::<StartContainerOptions<String>>).await {
        Ok(_) => {
            let connect_info = format!("{}:{}", state.config.public_host, 7777 + id as u16);
            
            let mut servers = state.servers.write().await;
            if let Some(server) = servers.get_mut(&id) {
                server.status = ServerStatus::Running;
                server.started_at = Some(now_timestamp());
                server.connect_info = Some(connect_info);
            }

            info!("Server {} started by {}", id, user.username);
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            error!("Failed to start server {}: {}", id, e);
            let mut servers = state.servers.write().await;
            if let Some(server) = servers.get_mut(&id) {
                server.status = ServerStatus::Stopped;
                server.started_by = None;
            }
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(format!("Start failed: {}", e)))))
        }
    }
}

async fn stop_server(
    Path(id): Path<u8>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if id < 1 || id > 2 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("Invalid server ID"))));
    }

    // Verify auth (optional for stop, but log who did it)
    let username = if let Some(token) = extract_token(&headers) {
        state.verify_dcf_token(&token).await.ok().map(|u| u.username)
    } else {
        None
    };

    {
        let servers = state.servers.read().await;
        if let Some(server) = servers.get(&id) {
            if server.status == ServerStatus::Stopped {
                return Err((StatusCode::CONFLICT, Json(ApiResponse::<()>::error("Already stopped"))));
            }
        }
    }

    {
        let mut servers = state.servers.write().await;
        if let Some(server) = servers.get_mut(&id) {
            server.status = ServerStatus::Stopping;
        }
    }

    let container_name = format!("gsn-server-{}", id);
    info!("Stopping {} (by {:?})", container_name, username);

    match state.docker.stop_container(&container_name, Some(StopContainerOptions { t: 30 })).await {
        Ok(_) => {
            let mut servers = state.servers.write().await;
            if let Some(server) = servers.get_mut(&id) {
                server.status = ServerStatus::Stopped;
                server.started_at = None;
                server.started_by = None;
                server.players = 0;
                server.connect_info = None;
            }
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            error!("Stop failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(format!("Stop failed: {}", e)))))
        }
    }
}

async fn load_game(
    Path(id): Path<u8>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoadGameRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if id < 1 || id > 2 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("Invalid server ID"))));
    }

    // Auth check
    if let Some(token) = extract_token(&headers) {
        if state.verify_dcf_token(&token).await.is_err() {
            return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("Invalid token"))));
        }
    }

    let game = {
        let games = state.games.read().await;
        match games.get(&req.game) {
            Some(g) => g.clone(),
            None => return Err((StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Game not found")))),
        }
    };

    {
        let servers = state.servers.read().await;
        if let Some(server) = servers.get(&id) {
            if server.status != ServerStatus::Stopped {
                return Err((StatusCode::CONFLICT, Json(ApiResponse::<()>::error("Stop server first"))));
            }
        }
    }

    let container_name = format!("gsn-server-{}", id);
    info!("Loading {} on {}", req.game, container_name);

    // Remove existing
    let _ = state.docker.remove_container(&container_name, Some(RemoveContainerOptions { force: true, ..Default::default() })).await;

    // Create with game config
    let env_vars: Vec<String> = game.env.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .chain(vec![
            format!("SERVER_ID={}", id),
            format!("GAME_ID={}", game.id),
        ])
        .collect();

    let config = Config {
        image: Some(game.image.clone()),
        env: Some(env_vars),
        labels: Some(HashMap::from([
            ("dcf.gsn".into(), "true".into()),
            ("dcf.game".into(), game.id.clone()),
        ])),
        ..Default::default()
    };

    match state.docker.create_container(Some(CreateContainerOptions { name: &container_name, platform: None }), config).await {
        Ok(_) => {
            let mut servers = state.servers.write().await;
            if let Some(server) = servers.get_mut(&id) {
                server.game = Some(game.name);
                server.game_image = Some(game.image);
                server.max_players = 32;
            }
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            error!("Create failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(format!("Load failed: {}", e)))))
        }
    }
}

async fn list_games(State(state): State<Arc<AppState>>) -> Json<ApiResponse<Vec<GameConfig>>> {
    let games = state.games.read().await;
    Json(ApiResponse::success(games.values().cloned().collect()))
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<ApiResponse<StatsResponse>> {
    let servers = state.servers.read().await;
    let active = servers.values().filter(|s| s.status == ServerStatus::Running).count() as u32;

    // In production, query DCF-ID for real stats
    Json(ApiResponse::success(StatsResponse {
        total_users: 0,
        active_servers: active,
        total_bandwidth_today: 0,
        total_bandwidth_month: 0,
    }))
}

// ============================================================================
// HELPERS
// ============================================================================
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn load_game_configs(state: Arc<AppState>) {
    let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "/config".into());
    let games_path = format!("{}/games", path);

    if let Ok(entries) = std::fs::read_dir(&games_path) {
        let mut games = state.games.write().await;
        for entry in entries.flatten() {
            if entry.path().extension().map_or(false, |e| e == "json") {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Ok(game) = serde_json::from_str::<GameConfig>(&content) {
                        info!("Loaded game: {}", game.id);
                        games.insert(game.id.clone(), game);
                    }
                }
            }
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    info!("Starting DeMoD Game Selector with DCF integration...");

    let config = AppConfig::from_env();
    info!("DCF-ID: {}", config.dcf_id_url);
    info!("Meter: {}", config.meter_url);

    let docker = Docker::connect_with_socket_defaults()?;

    let mut servers = HashMap::new();
    for id in 1..=2u8 {
        servers.insert(id, ServerState {
            id,
            name: format!("Server-{}", if id == 1 { "Alpha" } else { "Beta" }),
            status: ServerStatus::Stopped,
            game: None,
            game_image: None,
            players: 0,
            max_players: 0,
            started_at: None,
            started_by: None,
            connect_info: None,
        });
    }

    let state = Arc::new(AppState {
        config,
        docker,
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        servers: RwLock::new(servers),
        games: RwLock::new(HashMap::new()),
    });

    load_game_configs(Arc::clone(&state)).await;

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/servers", get(list_servers))
        .route("/api/servers/:id", get(get_server))
        .route("/api/servers/:id/start", post(start_server))
        .route("/api/servers/:id/stop", post(stop_server))
        .route("/api/servers/:id/load", post(load_game))
        .route("/api/games", get(list_games))
        .route("/api/stats", get(get_stats))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Listening on :8080");

    axum::serve(listener, app).await?;
    Ok(())
}
