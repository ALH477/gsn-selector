# 
FROM rust:1.83-alpine AS builder
# We only need musl-dev now; pkgconfig and openssl-dev are no longer required
RUN apk add --no-cache musl-dev 
WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
# Pre-build dependencies for caching
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
# Build the actual application
RUN touch src/main.rs && cargo build --release
# Strip the binary to reduce size
RUN strip /build/target/release/gsn-selector

FROM alpine:3.20
# 
RUN apk add --no-cache ca-certificates wget && adduser -D -u 1000 selector
WORKDIR /app
COPY --from=builder /build/target/release/gsn-selector .
USER selector
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1
CMD ["./gsn-selector"]
