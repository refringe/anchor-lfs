package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// TempFilePrefix starts the name of every temporary file written under the data directory.
const TempFilePrefix = ".tmp-"

// RemoveStaleTempFiles deletes temporary files under dir unmodified for over olderThan and returns how many it removed.
func RemoveStaleTempFiles(dir string, olderThan time.Duration) (int, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, fmt.Errorf("removing stale temporary files: %w", err)
	}
	defer func() { _ = root.Close() }()

	cutoff := time.Now().Add(-olderThan)
	removed := 0
	var problems []error
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == "." {
				return err
			}
			if !errors.Is(err, fs.ErrPermission) {
				problems = append(problems, err)
			}
			return fs.SkipDir
		}
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), TempFilePrefix) {
			return nil
		}
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			problems = append(problems, err)
			return nil
		}
		if info.ModTime().After(cutoff) {
			return nil
		}
		if err := root.Remove(path); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				problems = append(problems, err)
			}
			return nil
		}
		removed++
		return nil
	})
	if err = errors.Join(append(problems, err)...); err != nil {
		return removed, fmt.Errorf("removing stale temporary files: %w", err)
	}
	return removed, nil
}
