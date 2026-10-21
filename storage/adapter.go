// Package storage defines the object storage interface and provides implementations for local filesystem and
// S3-compatible object storage.
package storage

import (
	"context"
	"io"
	"time"
)

// Adapter is the interface for object storage backends; callers must bound the reader passed to Put.
type Adapter interface {
	Exists(ctx context.Context, endpoint, oid string) (bool, error)
	Get(ctx context.Context, endpoint, oid string) (io.ReadCloser, int64, error)
	Put(ctx context.Context, endpoint, oid string, reader io.Reader, size int64) error
	Size(ctx context.Context, endpoint, oid string) (int64, error)
	AvailableSpace(ctx context.Context) (uint64, error)
	Check(ctx context.Context) error
}

// PresignedURLProvider is implemented by adapters that hand out direct client-to-storage URLs instead of proxy URLs.
type PresignedURLProvider interface {
	PresignGet(ctx context.Context, endpoint, oid string, expiry time.Duration) (href string, err error)
	PresignPut(ctx context.Context, endpoint, oid string, size int64, expiry time.Duration) (href string, header map[string]string, err error)
}
