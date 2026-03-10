# Copilot Instructions for Anchor LFS

## Project Summary

Anchor LFS is a lightweight, self-hosted Git LFS server written in Go 1.26. It implements the Git LFS Batch API spec, authenticates against GitHub organisation/repository permissions, and supports local filesystem or S3-compatible object storage with SHA-256 integrity verification. The codebase is small (~3,000 lines of Go across 8 packages) with no web framework; routing uses `net/http` with `http.ServeMux`.

## Build, Test, and Validate

**Runtime:** Go 1.26+ (specified in `go.mod`). **Linter:** golangci-lint v2 (config version `"2"` in `.golangci.yml`).

Always run these commands from the repository root. The `Makefile` is the single source of truth for all commands.

| Task | Command | Notes |
|---|---|---|
| Install deps | `go mod download` | Run first after cloning |
| Build | `make build` | Output: `bin/anchor-lfs` |
| Run tests | `make test` | Runs `go test -race ./...` |
| Lint | `make lint` | Runs `golangci-lint run ./...` |
| Format check | `make fmt-check` | Fails if any file needs formatting |
| Format fix | `make fmt` | Runs `gofmt -w .` |
| Vet | `go vet ./...` | Also run in CI |
| Tidy check | `go mod tidy && git diff --exit-code go.mod go.sum` | CI rejects untidy modules |
| Full check | `make check` | Runs: fmt-check, lint, vet, vulncheck, test |

**Always run `make fmt` before committing.** Always run `make test` and `make lint` to validate changes. If you add or remove dependencies, run `go mod tidy` and include both `go.mod` and `go.sum` in the commit.

## CI Pipelines (GitHub Actions)

Four workflows run on every push/PR to `main` (in `.github/workflows/`):

1. **Format** (`format.yml`): `make fmt-check`
2. **Quality** (`quality.yml`): `golangci-lint`, `go vet ./...`, `go mod tidy` cleanliness check
3. **Tests** (`tests.yml`): `make test`
4. **Vulnerability** (`vulnerability.yml`): `govulncheck ./...`

A fifth workflow (`release.yml`) runs only on version tags and builds/publishes Docker images. All workflows use Go version from `go.mod`.

## Code Style Requirements

**UK English everywhere.** The linter enforces British English spelling via `misspell` with `locale: UK`. Use "colour" not "color", "authorise" not "authorize", "organisation" not "organization", etc. The only exception is when an external API enforces American English (e.g., Go stdlib function names like `filepath.Localize`).

**Linter rules to watch:**
- `nolintlint`: Every `//nolint:` directive must include both the specific linter name and a `// reason` comment. Example: `//nolint:gosec // path is operator-controlled`
- `goconst`: Strings used 3+ times should be constants
- `errorlint`: Use `errors.Is()` and `errors.As()` for error comparisons
- `bodyclose`: Always close HTTP response bodies
- Test files (`_test.go`) are exempt from `bodyclose`, `goconst`, `nilnil`, and `unparam`

**Other conventions:**
- Table-driven tests with `t.Helper()` on helpers
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Structured logging via `zerolog` (use `log` from `github.com/rs/zerolog/log`)
- Interface-based adapters with compile-time checks: `var _ Interface = (*Impl)(nil)`
- Dependency injection via config structs (e.g., `HandlerConfig`)

## Project Layout

```
.                           # Repository root (Go module: github.com/refringe/anchor-lfs)
├── main.go                 # Entry point: config loading, wiring, route registration, graceful shutdown
├── main_test.go            # Integration tests for the full server
├── config/
│   ├── config.go           # TOML parsing, env var overrides (ANCHOR_LFS_*), validation
│   └── config_test.go
├── auth/
│   ├── authenticator.go    # Authenticator interface, Operation and Result types
│   ├── github.go           # GitHub PAT authentication with TTL cache
│   ├── github_test.go
│   └── none.go             # No-op authenticator for local/test use
├── storage/
│   ├── adapter.go          # Adapter interface, PresignedURLProvider interface
│   ├── local.go            # Local filesystem storage (atomic writes, SHA-256 verify)
│   ├── local_unix.go       # Unix-specific disk space check (syscall.Statfs)
│   ├── local_windows.go    # Windows-specific disk space check
│   ├── local_test.go
│   ├── s3.go               # S3-compatible storage adapter
│   └── s3_test.go
├── lfs/
│   ├── handler.go          # HTTP handlers: Batch, Download, Upload, Verify, Lock CRUD
│   ├── handler_test.go
│   ├── batch.go            # Batch response building (processBatch)
│   ├── models.go           # Request/response JSON structs
│   ├── signer.go           # HMAC-signed URL generation and verification
│   ├── signer_test.go
│   ├── locks.go            # File lock store (JSON file-backed)
│   └── locks_test.go
├── middleware/
│   ├── ratelimit.go        # Per-IP rate limiting middleware
│   ├── ratelimit_test.go
│   ├── logging.go          # Structured request logging middleware
│   └── logging_test.go
├── internal/
│   ├── sanitise/           # Path sanitisation for endpoint directory names
│   └── testutil/           # Shared test helpers (e.g., SHA-256 computation)
├── Makefile                # All build/test/lint commands
├── .golangci.yml           # Linter configuration (27 linters, UK English)
├── config.toml.example     # Example configuration file
├── Dockerfile              # Multi-stage build (golang:1.26-alpine -> alpine:3.21)
├── docker-compose.yml      # Docker Compose for local development
└── .github/
    ├── workflows/          # CI pipelines (format, quality, tests, vulnerability, release)
    ├── CONTRIBUTING.md     # Contribution guidelines
    └── PULL_REQUEST_TEMPLATE.md
```

## API Routes

All routes are registered in `main.go` with explicit HTTP methods on `http.ServeMux`. Each endpoint prefix is configurable via `config.toml`:

- `POST {prefix}/objects/batch` — Transfer negotiation
- `GET {prefix}/objects/{oid}` — Download (HMAC-signed URL)
- `PUT {prefix}/objects/{oid}` — Upload (HMAC-signed URL)
- `POST {prefix}/objects/verify` — Integrity verification
- `POST/GET {prefix}/locks` — File locking
- `POST {prefix}/locks/verify` — Lock ownership verification
- `POST {prefix}/locks/{id}/unlock` — Unlock
- `GET /health` — Health check

## Configuration

Configuration is loaded from `config.toml` (see `config.toml.example`). Environment variables with the `ANCHOR_LFS_` prefix override TOML values. The config file path can be overridden with `ANCHOR_LFS_CONFIG`. Tests create their own config in temporary directories and do not require `config.toml` to exist.

## Key Dependencies

- `github.com/BurntSushi/toml` — TOML parsing
- `github.com/rs/zerolog` — Structured logging
- `github.com/sethvargo/go-limiter` — Rate limiting
- `github.com/google/go-github/v69` — GitHub API client
- `github.com/aws/aws-sdk-go-v2` — S3 storage backend

## Trust These Instructions

These instructions are validated and accurate. Only perform additional codebase searches if the information here is incomplete or found to be incorrect during your work.
