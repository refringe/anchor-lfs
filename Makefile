.PHONY: build dist run test test-cover lint vet fmt fmt-check prettier prettier-check vulncheck check tidy docker-build docker-up docker-down docker-logs clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/anchor-lfs .

# Release archives for every supported platform, with SHA-256 checksums
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

dist:
	rm -rf dist && mkdir dist
	@set -e; for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=anchor-lfs_$(patsubst v%,%,$(VERSION))_$${os}_$${arch}; \
		binary=anchor-lfs; if [ "$$os" = windows ]; then binary=anchor-lfs.exe; fi; \
		echo "building $$name"; \
		mkdir dist/$$name; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$$name/$$binary .; \
		cp LICENSE README.md config.toml.example dist/$$name/; \
		if [ "$$os" = windows ]; then (cd dist && zip -qr $$name.zip $$name); else tar -czf dist/$$name.tar.gz -C dist $$name; fi; \
		rm -r dist/$$name; \
	done
	cd dist && shasum -a 256 anchor-lfs_* > checksums.txt

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
	rm -rf bin/ dist/ coverage.out
