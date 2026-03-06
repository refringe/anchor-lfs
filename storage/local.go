package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/refringe/anchor-lfs/internal/sanitise"
)

// Compile-time interface check.
var _ Adapter = (*Local)(nil)

// ErrHashMismatch is returned when the computed SHA-256 hash of an uploaded
// object does not match the expected OID.
var ErrHashMismatch = errors.New("hash mismatch")

// ErrInsufficientStorage is returned when the filesystem has no space left.
var ErrInsufficientStorage = errors.New("insufficient storage")

// Local stores objects on the local filesystem.
type Local struct {
	basePath string
}

// NewLocal creates a Local storage adapter rooted at basePath.
func NewLocal(basePath string) *Local {
	return &Local{basePath: basePath}
}

// Exists reports whether the object exists in storage.
func (l *Local) Exists(ctx context.Context, endpoint, oid string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := os.Stat(l.filePath(endpoint, oid))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("checking object %s: %w", oid, err)
}

// Get opens the object for reading and returns its size.
func (l *Local) Get(ctx context.Context, endpoint, oid string) (io.ReadCloser, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	path := l.filePath(endpoint, oid)
	f, err := os.Open(path) //nolint:gosec // path is constructed from validated OID hex strings
	if err != nil {
		return nil, 0, fmt.Errorf("opening object %s: %w", oid, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat object %s: %w", oid, err)
	}
	return f, info.Size(), nil
}

// Put streams reader content to storage, verifying the SHA-256 hash matches
// the OID. The context is not checked during I/O because the reader (typically
// an http.Request.Body) will return an error when the client disconnects,
// which naturally terminates the io.Copy.
func (l *Local) Put(ctx context.Context, endpoint, oid string, reader io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	destPath := l.filePath(endpoint, oid)
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath) // No-op after successful rename.
	}()

	hasher := sha256.New()
	w := io.MultiWriter(tmp, hasher)

	if _, err := io.Copy(w, reader); err != nil {
		if isNoSpaceErr(err) {
			return fmt.Errorf("writing object: %w: %w", ErrInsufficientStorage, err)
		}
		return fmt.Errorf("writing object: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		if isNoSpaceErr(err) {
			return fmt.Errorf("syncing temp file: %w: %w", ErrInsufficientStorage, err)
		}
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	closed = true

	computed := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(computed, oid) {
		return fmt.Errorf("%w: expected %s, got %s", ErrHashMismatch, oid, computed)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("moving object to storage: %w", err)
	}
	return nil
}

// Size returns the size of the stored object in bytes.
func (l *Local) Size(ctx context.Context, endpoint, oid string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	info, err := os.Stat(l.filePath(endpoint, oid))
	if err != nil {
		return 0, fmt.Errorf("stat object %s: %w", oid, err)
	}
	return info.Size(), nil
}

// filePath returns the sharded storage path for the given OID.
// Callers must validate that oid is a 64-character hex string before calling
// this function (see lfs.isValidOID). Short OIDs are stored without sharding
// as a safety fallback.
func (l *Local) filePath(endpoint, oid string) string {
	if len(oid) < 4 {
		return filepath.Join(l.basePath, sanitise.Endpoint(endpoint), oid)
	}
	return filepath.Join(l.basePath, sanitise.Endpoint(endpoint), oid[:2], oid[2:4], oid)
}
