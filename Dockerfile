# Build stage: runs natively on the build host regardless of target platform. TARGETOS and TARGETARCH are set
# automatically by buildx, enabling native Go cross-compilation instead of slow QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o anchor-lfs .

# Runtime stage
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -S -g 101 anchor && adduser -S -u 100 -G anchor anchor \
    && mkdir -p /app/data && chown anchor:anchor /app/data
WORKDIR /app
COPY --from=builder /build/anchor-lfs .

USER anchor
EXPOSE 5420
HEALTHCHECK --interval=30s --timeout=15s --start-period=30s --retries=3 CMD ["./anchor-lfs", "healthcheck"]

ENTRYPOINT ["./anchor-lfs"]
