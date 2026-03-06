# Anchor LFS

A lightweight, standalone [Git LFS](https://git-lfs.com/) server written in Go that authenticates users against GitHub organisation and repository permissions.

## Features

- Full [Git LFS Batch API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md) compliance
- [File locking API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md) for coordinating concurrent edits
- GitHub-based authentication (checks pull/push permissions on your repo)
- Multiple repository endpoints from a single instance
- Local filesystem or S3-compatible object storage (AWS S3, Cloudflare R2, MinIO, etc.)
- HMAC-signed transfer URLs with configurable expiration
- SHA-256 integrity verification on upload
- Configurable per-endpoint visibility (public/private)
- Per-IP rate limiting with configurable token bucket
- Docker-first deployment

## Quick Start

### Docker

```bash
cp config.toml.example config.toml
# Edit config.toml with your endpoints, then:
docker compose up -d
```

### From Source

```bash
# Build
make build

# Edit config.toml, then run:
./bin/anchor-lfs
```

## Documentation

Full documentation is available on the **[Wiki](https://github.com/refringe/anchor-lfs/wiki)**:

- **[Installation](https://github.com/refringe/anchor-lfs/wiki/Installation):** Building from source and system requirements
- **[Docker](https://github.com/refringe/anchor-lfs/wiki/Docker):** Container deployment with Docker Compose
- **[Configuration](https://github.com/refringe/anchor-lfs/wiki/Configuration):** All global options, endpoints, and environment variables
- **[Storage Backends](https://github.com/refringe/anchor-lfs/wiki/Storage-Backends):** Local filesystem and S3-compatible storage setup
- **[Authentication](https://github.com/refringe/anchor-lfs/wiki/Authentication):** GitHub and GitHub Enterprise authentication
- **[Git LFS Client Setup](https://github.com/refringe/anchor-lfs/wiki/Git-LFS-Client-Setup):** Configuring your Git client
- **[File Locking](https://github.com/refringe/anchor-lfs/wiki/File-Locking):** Coordinating concurrent edits
- **[Reverse Proxy](https://github.com/refringe/anchor-lfs/wiki/Reverse-Proxy):** Running behind nginx, Caddy, or Traefik
- **[Security](https://github.com/refringe/anchor-lfs/wiki/Security):** Security model and best practices
- **[API Reference](https://github.com/refringe/anchor-lfs/wiki/API-Reference):** Endpoint routes and protocol details
- **[Troubleshooting](https://github.com/refringe/anchor-lfs/wiki/Troubleshooting):** Common issues and solutions

## Development

```bash
make build        # Compile binary to bin/anchor-lfs
make run          # Build and run
make test         # Run tests with race detector
make test-cover   # Run tests with coverage report
make lint         # Run golangci-lint
make fmt          # Format code
make vet          # Run go vet
make vulncheck    # Vulnerability scan
make check        # Run all checks (fmt, lint, vet, vulncheck, test)
make tidy         # Run go mod tidy
make clean        # Remove build artefacts
```

Docker commands:

```bash
make docker-build   # Build Docker image
make docker-up      # Start containers
make docker-down    # Stop containers
make docker-logs    # Tail container logs
```

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details.

## License

[AGPL-3.0](LICENSE)
