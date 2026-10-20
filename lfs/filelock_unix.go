//go:build !windows

package lfs

import (
	"errors"
	"os"
	"syscall"
)

// lockFile blocks until it holds an exclusive advisory lock on f.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

// unlockFile releases the advisory lock held on f.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
