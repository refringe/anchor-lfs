# Copilot Instructions for Anchor LFS

## Project Summary

Anchor LFS is a lightweight, self-hosted Git LFS server written in Go 1.27. It implements the Git LFS Batch API spec, authenticates against GitHub organisation/repository permissions, and supports local filesystem or S3-compatible object storage with SHA-256 integrity verification. The codebase is small (~3,000 lines of Go across 8 packages) with no web framework; routing uses `net/http` with `http.ServeMux`.

## Build, Test, and Validate

**Runtime:** Go 1.27+ (specified in `go.mod`; older local toolchains auto-download it via `GOTOOLCHAIN=auto`). **Linter:** golangci-lint v2 (config version `"2"` in `.golangci.yml`).

Always run these commands from the repository root. The `Makefile` is the single source of truth for all commands.

| Task | Command | Notes |
|---|---|---|
| Install deps | `go mod download` | Run first after cloning |
| Build | `make build` | Output: `bin/anchor-lfs` |
| Release archives | `make dist` | Archives for linux, darwin and windows on amd64 and arm64, plus `checksums.txt`, in `dist/` |
| Run tests | `make test` | Runs `go test -race ./...` |
| Lint | `make lint` | Runs `go tool -modfile=tools/go.mod golangci-lint run ./...` |
| Format check | `make fmt-check` | Fails if any Go file needs formatting |
| Format fix | `make fmt` | Runs `gofmt -w .` |
| Prettier check | `make prettier-check` | Fails if any JSON/YAML file needs formatting |
| Prettier fix | `make prettier` | Runs `prettier --write` over JSON/YAML |
| Vet | `make vet` | `go vet` for linux, darwin and windows; also run in CI |
| Vulnerability scan | `make vulncheck` | `go tool -modfile=tools/go.mod govulncheck` (pinned in `tools/go.mod`) |
| Tidy check | `make tidy && git diff --exit-code go.mod go.sum tools/go.mod tools/go.sum` | CI rejects untidy modules |
| Full check | `make check` | Runs: fmt-check, prettier-check, lint, vet, vulncheck, test |

**Always run `make fmt` before committing.** Always run `make test` and `make lint` to validate changes. If you add or remove dependencies, run `make tidy` and include both `go.mod` and `go.sum` in the commit.

## CI Pipelines (GitHub Actions)

Six workflows run on every push/PR to `develop` and `main` (in `.github/workflows/`):

1. **Format** (`format.yml`): jobs `Go Format` (`make fmt-check`) and `Prettier` (`make prettier-check`)
2. **Quality** (`quality.yml`): job `Lint`: `make tidy` cleanliness check for both modules, no-`replace`-directive check, `make vet` (linux, darwin and windows), `make lint`
3. **Tests** (`tests.yml`): jobs `Test` (`make test`), `Coverage` (`make test-cover`, uploads `coverage.out` as an artifact) and `S3 Integration` (runs `TestS3Integration*` against a RustFS container)
4. **Vulnerability** (`vulnerability.yml`): job `Vulnerability Check` (`make vulncheck`); also runs weekly (Monday 06:23 UTC) and on demand
5. **CodeQL** (`codeql.yml`): job `Analyse`, matrix over `actions` and `go`; also runs weekly (Monday 06:23 UTC) and on demand
6. **Docker** (`docker.yml`): job `Docker Build` builds the image for `linux/amd64` and `linux/arm64` without pushing, then runs `anchor-lfs version` in the amd64 image

A seventh workflow (`release.yml`) runs only on version tags. It checks the tagged commit is on `main` and whether it is the highest version tag, calls workflows 1 to 4 through `workflow_call`, then in separate least-privilege jobs builds and attests the `make dist` archives, publishes the Docker image (with an SBOM, `mode=max` provenance and a GitHub attestation), and creates the GitHub release with the archives and notes from `.github/scripts/release-notes.sh` (commits since the previous tag, grouped by conventional-commit type). The image's `latest` tag and the release's Latest badge move only for the highest version. All workflows use the Go version from `go.mod`, and every action is pinned to a commit SHA with a `# vX.Y.Z` comment that Dependabot keeps current.

The job display names above are the required status check contexts in the repository's `develop` branch ruleset, so renaming a job requires updating the ruleset. The repository also has a `main` ruleset blocking deletion and force-pushes.

## Code Style Requirements

**UK English everywhere.** The linter enforces British English spelling via `misspell` with `locale: UK`. Use "colour" not "color", "authorise" not "authorize", "organisation" not "organization", etc. The only exception is when an external API enforces American English (e.g., Go stdlib function names like `filepath.Localize`).

**Linter rules to watch:**
- `nolintlint`: Every `//nolint:` directive must include both the specific linter name and a `// reason` comment. Example: `//nolint:gosec // path is operator-controlled`
- `goconst`: Strings used 3+ times should be constants
- `errorlint`: Use `errors.Is()` and `errors.AsType[*T]()` for error comparisons
- `bodyclose`: Always close HTTP response bodies
- Test files (`_test.go`) are exempt from `bodyclose`, `goconst`, `nilnil`, and `unparam`

**Other conventions:**
- Table-driven tests with `t.Helper()` on helpers
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Structured logging via `zerolog` (use `log` from `github.com/rs/zerolog/log`, or `middleware.Logger(r.Context())` in request paths so lines carry `request_id`)
- Interface-based adapters with compile-time checks: `var _ Interface = (*Impl)(nil)`
- Dependency injection via config structs (e.g., `HandlerConfig`)
- OID validation belongs in the storage package (`storage.IsValidOID` regexp guard, `storage.ErrInvalidOID`); handlers call it first for 422 responses, and the adapters validate again before touching a path or key
- JSON via `encoding/json/v2` (`json.UnmarshalRead` for request bodies, `json.MarshalWrite`/`json.Marshal` for responses); use `omitzero` rather than `omitempty` on numeric and bool fields
- Modern stdlib over hand-rolled code: `slices`, `cmp`, `min`/`max`, `sync.WaitGroup.Go`, and the `uuid` package (`go fix ./...` should report nothing)

## Project Layout

```
.                           # Repository root (Go module: github.com/refringe/anchor-lfs)
├── cli.go                  # Command line: --config, check/healthcheck/version/help commands, redacted config printing
├── cli_test.go
├── main.go                 # Server: config loading, startup logging, wiring, route registration, temp file sweep, graceful shutdown
├── main_test.go            # Integration tests for the full server
├── readiness.go            # GET /ready checks and the `anchor-lfs healthcheck` subcommand (Docker HEALTHCHECK)
├── readiness_test.go
├── shutdown_unix_test.go   # Runs the server as a child process to test signals, the second-signal stop and exit codes
├── config/
│   ├── config.go           # TOML parsing, env var overrides (ANCHOR_LFS_*), validation
│   └── config_test.go
├── auth/
│   ├── authenticator.go    # Authenticator interface, Operation and Result types
│   ├── github.go           # GitHub PAT authentication, TTL cache per token and endpoint, single-flight lookups
│   ├── github_test.go
│   └── none.go             # No-op authenticator for local/test use
├── storage/
│   ├── adapter.go          # Adapter interface, PresignedURLProvider interface
│   ├── local.go            # Local filesystem storage (atomic writes, SHA-256 verify)
│   ├── local_unix.go       # Unix-specific disk space check (syscall.Statfs)
│   ├── local_windows.go    # Windows-specific disk space check
│   ├── local_test.go
│   ├── s3.go               # S3-compatible storage adapter (S3 proxies, PresignedS3 presigns)
│   ├── s3_integration_test.go # Runs against a real S3 server when ANCHOR_LFS_TEST_S3_ENDPOINT is set
│   ├── s3_test.go
│   ├── tempfiles.go        # TempFilePrefix and RemoveStaleTempFiles (hourly sweep of interrupted writes)
│   └── tempfiles_test.go
├── lfs/
│   ├── handler.go          # HTTP handlers: Batch, Download, Upload, Verify, Lock CRUD
│   ├── handler_test.go
│   ├── batch.go            # Batch response building (processBatch, up to 16 objects looked up at once, in order)
│   ├── body.go             # readErrorRecorder: keeps an upload body's read error (interrupted upload, 400)
│   ├── idle.go             # Per-read idle deadline on upload bodies (upload_idle_timeout, 408 on a stall)
│   ├── idle_test.go
│   ├── models.go           # Request/response JSON structs
│   ├── signer.go           # HMAC-signed URL generation and verification
│   ├── signer_test.go
│   ├── locks.go            # File lock store (JSON file-backed, indexed in memory, cross-process file lock on writes)
│   ├── locks_test.go
│   ├── filelock_unix.go    # Unix advisory file lock (syscall.Flock)
│   └── filelock_windows.go # Windows file lock (LockFileEx)
├── middleware/
│   ├── proxy.go            # Trusted-proxy handling: strips untrusted X-Forwarded-* headers, resolves client IPs
│   ├── proxy_test.go
│   ├── requestid.go        # Request IDs (X-Request-ID header, context, request-scoped logger)
│   ├── requestid_test.go
│   ├── ratelimit.go        # Per-IP rate limiting middleware
│   ├── ratelimit_test.go
│   ├── logging.go          # Structured request logging middleware
│   └── logging_test.go
├── internal/
│   ├── sanitise/           # Path sanitisation for endpoint directory names (letters, digits, ., _, -; no leading dot)
│   └── testutil/           # Shared test helpers (e.g., SHA-256 computation)
├── Makefile                # All build/test/lint commands
├── tools/go.mod            # Separate module pinning golangci-lint and govulncheck as tool dependencies
├── .golangci.yml           # Linter configuration (23 linters, UK English)
├── .prettierrc.json        # Prettier configuration (JSON/YAML formatting)
├── config.toml.example     # Example configuration file
├── Dockerfile              # Multi-stage build (golang:1.27-alpine -> alpine:3.24, both digest-pinned)
├── docker-compose.yml      # Docker Compose deployment of ghcr.io/refringe/anchor-lfs:latest, read-only with all capabilities dropped
└── .github/
    ├── workflows/          # CI pipelines (format, quality, tests, vulnerability, codeql, docker, release)
    ├── scripts/            # release-notes.sh: release notes grouped by commit type, used by release.yml
    ├── CONTRIBUTING.md     # Contribution guidelines
    └── PULL_REQUEST_TEMPLATE.md
```

## API Routes

All endpoint routes are registered in `registerRoutes` in `main.go` with explicit HTTP methods on `http.ServeMux`. Batch and lock routes are rate limited per IP; the HMAC-signed transfer routes are not. Each endpoint prefix is configurable via `config.toml`:

- `POST {prefix}/objects/batch`: Transfer negotiation (objects looked up in storage 16 at a time)
- `GET {prefix}/objects/{oid}`: Download (HMAC-signed URL)
- `PUT {prefix}/objects/{oid}`: Upload (HMAC-signed URL)
- `POST {prefix}/objects/verify`: Integrity verification (HMAC-signed URL)
- `POST/GET {prefix}/locks`: File locking
- `POST {prefix}/locks/verify`: Lock ownership verification
- `POST {prefix}/locks/{id}/unlock`: Unlock
- `GET /health`: Liveness check
- `GET /ready`: Readiness check (data directory and storage backend)
- `GET /`: Version; every other path and method gets a JSON 404 (`registerServiceRoutes`)

## Configuration

Configuration is loaded from `config.toml` (see `config.toml.example`). Environment variables with the `ANCHOR_LFS_` prefix override TOML values, and the signing key and S3 credentials also take a `_FILE` variant that names a file holding the value. The config file path comes from `--config`, then `ANCHOR_LFS_CONFIG`, then `config.toml` (`config.ResolvePath`), and `anchor-lfs check` validates a file and prints it with secrets redacted. Tests create their own config in temporary directories and do not require `config.toml` to exist.

## Key Dependencies

- `github.com/BurntSushi/toml`: TOML parsing
- `github.com/rs/zerolog`: Structured logging
- `github.com/sethvargo/go-limiter`: Rate limiting
- `github.com/google/go-github/v69`: GitHub API client
- `github.com/aws/aws-sdk-go-v2`: S3 storage backend

## Trust These Instructions

These instructions are validated and accurate. Only perform additional codebase searches if the information here is incomplete or found to be incorrect during your work.
