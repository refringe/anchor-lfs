//go:build windows

package storage

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// AvailableSpace returns the number of bytes available for the current user
// on the filesystem that contains the storage base path.
func (l *Local) AvailableSpace(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var freeBytesAvailable uint64
	pathPtr, err := syscall.UTF16PtrFromString(l.basePath)
	if err != nil {
		return 0, fmt.Errorf("encoding path: %w", err)
	}

	ret, _, callErr := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		0,
		0,
	)
	if ret == 0 {
		return 0, fmt.Errorf("GetDiskFreeSpaceExW %s: %w", l.basePath, callErr)
	}
	return freeBytesAvailable, nil
}

// isNoSpaceErr reports whether err indicates the filesystem has no space left.
func isNoSpaceErr(err error) bool {
	// ERROR_DISK_FULL (0x70 / 112) and ERROR_HANDLE_DISK_FULL (0x27 / 39).
	return errors.Is(err, syscall.Errno(0x70)) || errors.Is(err, syscall.Errno(0x27))
}
