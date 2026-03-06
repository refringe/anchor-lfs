//go:build !windows

package storage

import (
	"context"
	"errors"
	"fmt"
	"syscall"
)

// AvailableSpace returns the number of bytes available for non-privileged
// users on the filesystem that contains the storage base path.
func (l *Local) AvailableSpace(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(l.basePath, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", l.basePath, err)
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

// isNoSpaceErr reports whether err indicates the filesystem has no space left.
func isNoSpaceErr(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}
