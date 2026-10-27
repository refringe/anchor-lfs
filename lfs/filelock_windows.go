//go:build windows

package lfs

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	procLockFileEx   = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	procUnlockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")
)

const lockfileExclusiveLock = 0x2

// lockFile blocks until it holds an exclusive lock on the first byte of f.
func lockFile(f *os.File) error {
	return lockFileEx(f, lockfileExclusiveLock)
}

// lockFileShared blocks until it holds a shared lock on the first byte of f.
func lockFileShared(f *os.File) error {
	return lockFileEx(f, 0)
}

// lockFileEx blocks until it holds a lock on the first byte of f, taken with the given LockFileEx flags.
func lockFileEx(f *os.File, flags uintptr) error {
	var ol syscall.Overlapped
	ret, _, callErr := procLockFileEx.Call(
		f.Fd(),
		flags,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)), //nolint:gosec // required for the LockFileEx syscall
	)
	if ret == 0 {
		return callErr
	}
	return nil
}

// unlockFile releases the lock held on the first byte of f.
func unlockFile(f *os.File) error {
	var ol syscall.Overlapped
	ret, _, callErr := procUnlockFileEx.Call(
		f.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)), //nolint:gosec // required for the UnlockFileEx syscall
	)
	if ret == 0 {
		return callErr
	}
	return nil
}
