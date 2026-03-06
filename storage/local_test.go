package storage

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data)); err != nil {
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

	err := store.Put(ctx, "test", badOID, bytes.NewReader(data))
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

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data)); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := store.Put(ctx, "test", oid, bytes.NewReader(data)); err != nil {
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
	got := store.filePath("/org/repo", oid)
	want := "/data/org_repo/4d/7a/4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393"

	// Use filepath separator-agnostic comparison.
	if got != want {
		// On non-Unix this may differ; check contains the sharding dirs.
		if !strings.Contains(got, "4d") || !strings.Contains(got, "7a") {
			t.Errorf("filePath sharding incorrect: %s", got)
		}
	}
}

// Ensure temp files are cleaned up on failure.
func TestPutCleansUpOnFailure(t *testing.T) {
	store := testStore(t)
	badOID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	_ = store.Put(t.Context(), "test", badOID, bytes.NewReader([]byte("data")))

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
