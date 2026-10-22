.PHONY: build run test test-cover lint vet fmt fmt-check prettier prettier-check vulncheck check tidy docker-build docker-up docker-down docker-logs clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Build
build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/anchor-lfs .

run: build
	./bin/anchor-lfs

# Quality
test:
	go test -race ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	go tool golangci-lint run ./...

vet:
	GOOS=linux go vet ./...
	GOOS=darwin go vet ./...
	GOOS=windows go vet ./...

fmt:
	gofmt -w .

fmt-check:
	test -z "$$(gofmt -l .)"

prettier:
	npx --yes prettier@3 --write '**/*.json' '**/*.yml'

prettier-check:
	npx --yes prettier@3 --check '**/*.json' '**/*.yml'

vulncheck:
	go tool govulncheck ./...

check: fmt-check prettier-check lint vet vulncheck test

# Dependencies
tidy:
	go mod tidy

# Docker
docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t anchor-lfs .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f anchor-lfs

# Clean
clean:
	rm -rf bin/ coverage.out
