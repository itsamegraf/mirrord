FROM ghcr.io/metalbear-co/ci-agent-build:latest AS builder
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY backend/Cargo.toml backend/Cargo.toml
COPY backend/src backend/src
RUN cargo build -p capabilities-rust-backend

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

RUN --mount=type=bind,from=builder,source=/app/target,target=/builder-target,ro \
    cp "/builder-target/debug/capabilities-rust-backend" /app/capabilities-rust-backend

ENTRYPOINT ["/app/capabilities-rust-backend"]
