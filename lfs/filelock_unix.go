//go:build !windows

package lfs

import (
	"errors"
	"os"
	"syscall"
)

// lockFile blocks until it holds an exclusive advisory lock on f.
func lockFile(f *os.File) error {
	return flock(f, syscall.LOCK_EX)
}

// lockFileShared blocks until it holds a shared advisory lock on f.
func lockFileShared(f *os.File) error {
	return flock(f, syscall.LOCK_SH)
}

// flock applies the advisory lock operation how to f, retrying when interrupted.
func flock(f *os.File, how int) error {
	for {
		err := syscall.Flock(int(f.Fd()), how)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

// unlockFile releases the advisory lock held on f.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
