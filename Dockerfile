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
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

RUN addgroup -S anchor && adduser -S anchor -G anchor
WORKDIR /app
COPY --from=builder /build/anchor-lfs .

USER anchor
EXPOSE 5420

ENTRYPOINT ["./anchor-lfs"]
