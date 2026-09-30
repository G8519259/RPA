# Prebuilt binaries & Docker

Compiled with Rust 1.92.0.

## Binaries (Linux, dynamically linked / glibc)

| File | Arch | Notes |
|------|------|-------|
| `rust_proxy_admin-linux-x86_64.gz` | x86-64 (amd64) | for Intel/AMD servers |
| `rust_proxy_admin-linux-arm64.gz`  | aarch64 (arm64) | for ARM servers, Apple Silicon Linux VMs, Raspberry Pi (64-bit) |

Verify and use:

```bash
sha256sum -c SHA256SUMS.txt          # optional integrity check
gunzip rust_proxy_admin-linux-arm64.gz
chmod +x rust_proxy_admin-linux-arm64
./rust_proxy_admin-linux-arm64 --help
```

> These are **glibc** builds — they need a glibc-based distro (Debian/Ubuntu/Fedora/AL2023, etc.), not musl-only Alpine.

## Docker

A multi-stage `Dockerfile` and `docker-compose.yml` live in the repo root. The image builds
from source, so it works natively on both amd64 and arm64 hosts.

```bash
# build
docker build -t rustproxyadmin:latest .

# run
docker run -d --name rpa -p 8080:8080 -v rpa-data:/app/data rustproxyadmin:latest
# open http://127.0.0.1:8080/admin   (default login admin / ChangeMe123!)

# or with compose
docker compose up -d --build
```

Override config via `RPA__SECTION__KEY` env vars (e.g. `RPA__AUTH__INIT_PASSWORD`).
The SQLite database is stored in the `/app/data` volume.

> ⚠️ Change the default admin password before exposing the panel publicly.
