// Package storage defines the object storage interface and provides implementations for local filesystem and
// S3-compatible object storage.
package storage

import (
	"context"
	"io"
	"time"
)

// Adapter is the interface for object storage backends.
//
// All methods accept a context.Context for cancellation. Implementations
// should check ctx.Err() before starting work. For streaming operations
// like Put, the context may not be monitored during I/O — callers should
// not rely on context cancellation to immediately abort an in-progress
// write. Network-backed implementations (e.g., S3) should propagate the
// context into their underlying client calls.
//
// Put does not enforce a size limit on the reader. Callers are responsible
// for wrapping the reader with an appropriate limit (e.g., http.MaxBytesReader)
// before passing it to Put.
type Adapter interface {
	Exists(ctx context.Context, endpoint, oid string) (bool, error)
	Get(ctx context.Context, endpoint, oid string) (io.ReadCloser, int64, error)
	Put(ctx context.Context, endpoint, oid string, reader io.Reader) error
	Size(ctx context.Context, endpoint, oid string) (int64, error)
	AvailableSpace(ctx context.Context) (uint64, error)
}

// PresignedURLProvider is an optional interface that storage adapters can implement to provide presigned URLs for direct
// client-to-storage transfers. When an adapter implements this interface, the batch handler uses the presigned URLs
// instead of generating HMAC-signed proxy URLs. The local filesystem adapter does not implement this interface.
type PresignedURLProvider interface {
	PresignGet(ctx context.Context, endpoint, oid string, expiry time.Duration) (href string, err error)
	PresignPut(ctx context.Context, endpoint, oid string, expiry time.Duration) (href string, err error)
}
