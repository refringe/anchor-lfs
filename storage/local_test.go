package storage

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/refringe/anchor-lfs/internal/sanitise"
	"github.com/refringe/anchor-lfs/internal/testutil"
)

func testStore(t *testing.T) *Local {
	t.Helper()
	dir := t.TempDir()
	return NewLocal(dir)
}

func TestPutAndGet(t *testing.T) {
	store := testStore(t)
	data := []byte("hello world")
	oid := testutil.SHA256Hex(data)

	ctx := t.Context()

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	exists, err := store.Exists(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected object to exist")
	}

	size, err := store.Size(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != int64(len(data)) {
		t.Fatalf("expected size %d, got %d", len(data), size)
	}

	reader, gotSize, err := store.Get(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if gotSize != int64(len(data)) {
		t.Fatalf("Get size: expected %d, got %d", len(data), gotSize)
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data mismatch")
	}
}

func TestPutHashMismatch(t *testing.T) {
	store := testStore(t)
	data := []byte("hello world")
	badOID := "0000000000000000000000000000000000000000000000000000000000000000"

	ctx := t.Context()

	err := store.Put(ctx, "test", badOID, bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}

	exists, err := store.Exists(ctx, "test", badOID)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("object should not exist after hash mismatch")
	}
}

func TestExistsNotFound(t *testing.T) {
	store := testStore(t)
	exists, err := store.Exists(t.Context(), "test", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected object to not exist")
	}
}

func TestGetNotFound(t *testing.T) {
	store := testStore(t)
	_, _, err := store.Get(t.Context(), "test", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Fatal("expected error for missing object")
	}
}

func TestPutIdempotent(t *testing.T) {
	store := testStore(t)
	data := []byte("hello world")
	oid := testutil.SHA256Hex(data)

	ctx := t.Context()

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := store.Put(ctx, "test", oid, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("second Put: %v", err)
	}
}

func TestSanitizeEndpoint(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/org/repo", "org_repo"},
		{"org/repo", "org_repo"},
		{"/a/b/c", "a_b_c"},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		got := sanitise.Endpoint(tt.input)
		if got != tt.want {
			t.Errorf("sanitise.Endpoint(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeEndpointRejectsTraversal(t *testing.T) {
	dangerous := []string{
		"..",
		"../etc",
		"foo/../bar",
		".",
	}
	for _, input := range dangerous {
		got := sanitise.Endpoint(input)
		if got != sanitise.InvalidEndpoint {
			t.Errorf("sanitise.Endpoint(%q) = %q, want %q", input, got, sanitise.InvalidEndpoint)
		}
	}
}

func TestFilePathSharding(t *testing.T) {
	store := NewLocal("/data")
	oid := "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393"
	want := filepath.Join("/data", "org_repo", "4d", "7a", oid)

	for _, input := range []string{oid, strings.ToUpper(oid)} {
		got, err := store.filePath("/org/repo", input)
		if err != nil {
			t.Fatalf("filePath(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("filePath(%q) = %q, want %q", input, got, want)
		}
	}
}

// Ensure temp files are cleaned up on failure.
func TestPutCleansUpOnFailure(t *testing.T) {
	store := testStore(t)
	badOID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	_ = store.Put(t.Context(), "test", badOID, bytes.NewReader([]byte("data")), 4)

	// Walk the entire storage tree to check for orphaned temp files.
	err := filepath.WalkDir(store.basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up: %s", path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("WalkDir: %v", err)
	}
}

// pausingReader returns head, then closes paused and waits for resume before returning tail.
type pausingReader struct {
	head, tail     io.Reader
	paused, resume chan struct{}
	once           sync.Once
}

func (r *pausingReader) Read(p []byte) (int, error) {
	if n, err := r.head.Read(p); !errors.Is(err, io.EOF) {
		return n, err
	}
	r.once.Do(func() {
		close(r.paused)
		<-r.resume
	})
	return r.tail.Read(p)
}

func TestPutTempFileSurvivesSweepWhileWriting(t *testing.T) {
	store := testStore(t)
	data := []byte("hello world")
	oid := testutil.SHA256Hex(data)
	body := &pausingReader{head: bytes.NewReader(data[:5]), tail: bytes.NewReader(data[5:]),
		paused: make(chan struct{}), resume: make(chan struct{})}

	done := make(chan error, 1)
	go func() { done <- store.Put(t.Context(), "/org/repo", oid, body, -1) }()
	select {
	case <-body.paused:
	case err := <-done:
		t.Fatalf("Put returned before reading the whole body: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(store.basePath, "org_repo", oid[:2], oid[2:4], TempFilePrefix+"*"))
	if err != nil || len(matches) != 1 {
		close(body.resume)
		t.Fatalf("temporary files = %v (error %v), want one", matches, err)
	}
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(matches[0], twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(store.basePath, matches[0])
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.ToSlash(rel)
	if !store.Writing(path) {
		t.Errorf("Writing(%q) = false during Put", path)
	}
	removed, err := RemoveStaleTempFiles(store.basePath, time.Hour, store.Writing)
	if err != nil || removed != 0 {
		t.Errorf("RemoveStaleTempFiles = %d, %v; want 0, nil", removed, err)
	}

	close(body.resume)
	if err := <-done; err != nil {
		t.Fatalf("Put: %v", err)
	}
	if store.Writing(path) {
		t.Errorf("Writing(%q) = true after Put returned", path)
	}
}

func TestRejectsInvalidOID(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	valid := "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393"

	invalid := []string{
		"",
		"..",
		"../../../../../../../../../../../../../../../../../../../../etc/passwd",
		"abc",
		valid[:63],
		valid + "0",
		"zz7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
		"4d/a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
		"4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e239\x00",
	}
	for _, oid := range invalid {
		if _, err := store.Exists(ctx, "test", oid); !errors.Is(err, ErrInvalidOID) {
			t.Errorf("Exists(%q) error = %v, want ErrInvalidOID", oid, err)
		}
		if _, _, err := store.Get(ctx, "test", oid); !errors.Is(err, ErrInvalidOID) {
			t.Errorf("Get(%q) error = %v, want ErrInvalidOID", oid, err)
		}
		if _, err := store.Size(ctx, "test", oid); !errors.Is(err, ErrInvalidOID) {
			t.Errorf("Size(%q) error = %v, want ErrInvalidOID", oid, err)
		}
		if err := store.Put(ctx, "test", oid, bytes.NewReader([]byte("data")), 4); !errors.Is(err, ErrInvalidOID) {
			t.Errorf("Put(%q) error = %v, want ErrInvalidOID", oid, err)
		}
	}

	entries, err := os.ReadDir(store.basePath)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files written for invalid OIDs, found %d entries", len(entries))
	}
}

func TestUppercaseOIDResolvesToSameObject(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	data := []byte("hello world")
	oid := testutil.SHA256Hex(data)

	if err := store.Put(ctx, "test", strings.ToUpper(oid), bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	exists, err := store.Exists(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected object stored under uppercase OID to be found by lowercase OID")
	}
}

func TestLocalCheck(t *testing.T) {
	if err := testStore(t).Check(t.Context()); err != nil {
		t.Fatalf("Check on a writable directory: %v", err)
	}

	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // directories need the execute bit to be traversable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // directories need the execute bit to be traversable
	if err := NewLocal(dir).Check(t.Context()); err == nil || !strings.Contains(err.Error(), "is not writable") {
		t.Fatalf("Check on a read-only directory = %v, want a not writable error", err)
	}
}
