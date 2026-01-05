# GSN Selector

GSN Selector is a game server orchestration service designed to integrate with the DeMoD Cloud Fabric (DCF) ecosystem. It manages the lifecycle of game server containers based on user authentication, account balance, and bandwidth quotas. 

## Overview

The service acts as a bridge between the DCF-ID authentication system and a local Docker engine. It ensures that game servers are only provisioned for authorized users who meet the minimum requirements for server uptime and data usage.

### Key Features

* **DCF-ID Integration**: Verifies user tokens and Discord-linked accounts against the DCF-ID API.
* **Orchestration**: Dynamically starts, stops, and reloads game server containers using the Docker API.
* **Resource Management**: Enforces maximum active server limits and checks for sufficient user balances before starting resources.
* **Usage Tracking**: Integrates with GSN-Meter for session registration and bandwidth monitoring.

## Deployment

### Prerequisites

* A running Docker engine.
* Access to a DCF-ID instance for authentication.
* A GSN-Meter instance for session tracking.

### Running the Container

The container requires access to the host Docker socket to manage game server containers. Use the following command to start the service:

```bash
docker run -d \
  --name gsn-selector \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e DCF_ID_URL=http://dcf-id-api:4000 \
  -e METER_URL=http://gsn-meter:9000 \
  -e DCF_ID_INTERNAL_KEY=your_secret_key \
  alh477/gsn-selector:latest

```

### Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `MAX_ACTIVE_SERVERS` | Maximum concurrent game servers allowed. | 2 |
| `DCF_ID_URL` | Endpoint for the DCF-ID authentication service. | http://dcf-id:4000 |
| `METER_URL` | Endpoint for the GSN-Meter session service. | http://gsn-meter:9000 |
| `MIN_BALANCE_TO_START` | Minimum account balance required to start a server. | 0.0 |
| `PUBLIC_HOST` | The public hostname for server connection strings. | dcf.demod.ltd |

## API Endpoints

* **GET /health**: Service health check.
* **GET /api/servers**: List all managed server slots and their status.
* **POST /api/servers/:id/start**: Authenticate and start a specific server.
* **POST /api/servers/:id/stop**: Stop a running server.
* **POST /api/servers/:id/load**: Reconfigure a server slot with a specific game image.

---

## License

Copyright (c) 2025-2026, DeMoD LLC. All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of DeMoD LLC nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
