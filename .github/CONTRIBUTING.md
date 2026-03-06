# Contributing to Anchor LFS

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository and clone your fork
2. Install Go 1.26+
3. Install dependencies: `go mod download`
4. Copy and configure: `cp config.toml config.local.toml` (edit as needed)
5. Run locally: `make run`

## Development

### Running checks

Before submitting a PR, run the full check suite:

```bash
make check
```

This runs: format check, linter, vet, vulnerability scan, and tests.

### Individual commands

```bash
make fmt          # Format code
make test         # Run tests with race detector
make lint         # Run golangci-lint
make vet          # Run go vet
make vulncheck    # Run govulncheck
```

## Pull Requests

- One concern per PR
- Write tests for new functionality
- Run `make check` before submitting
- Follow existing code style (run `make fmt`)
- Fill out the PR template

## Issues

- Use the bug report template for bugs
- Use the feature request template for suggestions
- Look for issues labeled `good first issue` or `help wanted`

## Bug Reports

Please include:
- Steps to reproduce
- Expected vs actual behavior
- Version or commit hash
- Deployment method (Docker / Binary / Source)
- Relevant logs
