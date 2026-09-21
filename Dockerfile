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
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN addgroup -S anchor && adduser -S anchor -G anchor
WORKDIR /app
COPY --from=builder /build/anchor-lfs .

USER anchor
EXPOSE 5420

ENTRYPOINT ["./anchor-lfs"]
