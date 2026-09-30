# syntax=docker/dockerfile:1

##############################
# Stage 1: build             #
##############################
# Uses the native architecture of the build host (amd64 or arm64).
# Rust >= 1.88 required by the project; some transitive deps need edition2024 (>= 1.85).
FROM rust:1.90-bookworm AS builder

WORKDIR /app

# Cache dependencies first: copy only the manifests, then fetch.
COPY Cargo.toml Cargo.lock ./
# Create a dummy main so `cargo fetch` has something to resolve against.
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo fetch

# Now copy the real sources and build.
COPY . .
# Touch main.rs so cargo picks up the real one over the dummy layer.
RUN touch src/main.rs \
    && cargo build --release \
    && strip target/release/rust_proxy_admin || true

##############################
# Stage 2: runtime           #
##############################
# Debian slim gives us glibc + CA certificates for outbound TLS (reqwest/lettre).
FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for HTTPS (subscription import, Telegram, SMTP, webhooks).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user.
RUN useradd -r -u 10001 -m -d /app rpa
WORKDIR /app

# Binary
COPY --from=builder /app/target/release/rust_proxy_admin /usr/local/bin/rust_proxy_admin

# Runtime assets the app reads from the working directory:
#   - templates/  (Tera templates, loaded via templates/**/*)
#   - static/     (served at /static)
#   - config.toml (default config; override with RPA__* env vars)
# (DB migrations are embedded in the binary via sqlx::migrate!, so not needed here.)
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/config.toml ./config.toml

# SQLite data lives here; declare a volume so it can be persisted.
RUN mkdir -p /app/data && chown -R rpa:rpa /app
VOLUME ["/app/data"]

USER rpa
EXPOSE 8080

# Bind to all interfaces inside the container by default.
ENV RPA__SERVER__BIND=0.0.0.0:8080 \
    RPA__DB__URL=sqlite://data/data.db

ENTRYPOINT ["rust_proxy_admin"]
