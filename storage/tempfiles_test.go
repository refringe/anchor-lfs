package storage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRemoveStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	oid := strings.Repeat("ab", 32)
	writeFile := func(name string, modified time.Time) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
		return path
	}

	staleObject := writeFile("org_repo/ab/ab/.tmp-123", twoHoursAgo)
	staleLocks := writeFile("locks/org_repo/.tmp-locks-456", twoHoursAgo)
	kept := []string{
		writeFile("org_repo/ab/ab/.tmp-789", time.Now()),
		writeFile("org_repo/ab/ab/"+oid, twoHoursAgo),
		writeFile("locks/org_repo/locks.json", twoHoursAgo),
		writeFile("signing.key", twoHoursAgo),
	}

	removed, err := RemoveStaleTempFiles(dir, time.Hour, nil)
	if err != nil {
		t.Fatalf("RemoveStaleTempFiles: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	for _, path := range []string{staleObject, staleLocks} {
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale temporary file %s still exists (stat error %v)", path, err)
		}
	}
	for _, path := range kept {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}
}

func TestRemoveStaleTempFilesSkipsUnreadableDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read every directory")
	}
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "lost+found")
	if err := os.Mkdir(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "org_repo", TempFilePrefix+"123")
	if err := os.MkdirAll(filepath.Dir(stale), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}

	removed, err := RemoveStaleTempFiles(dir, time.Hour, nil)
	if err != nil {
		t.Fatalf("RemoveStaleTempFiles: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale temporary file %s still exists (stat error %v)", stale, err)
	}
}

func TestRemoveStaleTempFilesKeepsFilesInUse(t *testing.T) {
	dir := t.TempDir()
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	busy := filepath.Join(dir, "org_repo", TempFilePrefix+"busy")
	idle := filepath.Join(dir, "org_repo", TempFilePrefix+"idle")
	if err := os.MkdirAll(filepath.Dir(busy), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{busy, idle} {
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, twoHoursAgo, twoHoursAgo); err != nil {
			t.Fatal(err)
		}
	}
	inUse := func(path string) bool { return path == "org_repo/"+TempFilePrefix+"busy" }

	removed, err := RemoveStaleTempFiles(dir, time.Hour, inUse)
	if err != nil {
		t.Fatalf("RemoveStaleTempFiles: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(busy); err != nil {
		t.Errorf("temporary file in use was removed: %v", err)
	}
	if _, err := os.Stat(idle); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale temporary file %s still exists (stat error %v)", idle, err)
	}
}

func TestRemoveStaleTempFilesIgnoresSymlinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, TempFilePrefix+"outside")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(target, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Skipf("creating symlink: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, TempFilePrefix+"link")); err != nil {
		t.Skipf("creating symlink: %v", err)
	}

	removed, err := RemoveStaleTempFiles(dir, time.Hour, nil)
	if err != nil {
		t.Fatalf("RemoveStaleTempFiles: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("file outside the directory was removed: %v", err)
	}
}

func TestRemoveStaleTempFilesMissingDirectory(t *testing.T) {
	if _, err := RemoveStaleTempFiles(filepath.Join(t.TempDir(), "missing"), time.Hour, nil); err == nil {
		t.Error("RemoveStaleTempFiles on a missing directory succeeded")
	}
}
