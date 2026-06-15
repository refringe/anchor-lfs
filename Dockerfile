# Build stage: runs natively on the build host regardless of target platform. TARGETOS and TARGETARCH are set
# automatically by buildx, enabling native Go cross-compilation instead of slow QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

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
FROM alpine:3.24@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4

RUN addgroup -S anchor && adduser -S anchor -G anchor
WORKDIR /app
COPY --from=builder /build/anchor-lfs .

USER anchor
EXPOSE 5420

ENTRYPOINT ["./anchor-lfs"]
