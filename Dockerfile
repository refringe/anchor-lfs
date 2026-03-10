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
FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709

RUN addgroup -S anchor && adduser -S anchor -G anchor
WORKDIR /app
COPY --from=builder /build/anchor-lfs .

USER anchor
EXPOSE 5420

ENTRYPOINT ["./anchor-lfs"]
