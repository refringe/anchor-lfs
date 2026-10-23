package lfs

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
	"uuid"
)

func TestFileLockStoreCreateAndList(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	lock, err := s.Create(ctx, "/repo", "path/to/file.dat", "alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if lock.Path != "path/to/file.dat" {
		t.Errorf("Path = %q, want %q", lock.Path, "path/to/file.dat")
	}
	if lock.Owner.Name != "alice" {
		t.Errorf("Owner = %q, want %q", lock.Owner.Name, "alice")
	}
	if lock.ID == "" {
		t.Fatal("expected non-empty lock ID")
	}
	if lock.LockedAt == "" {
		t.Fatal("expected non-empty LockedAt")
	}

	locks, nextCursor, err := s.List(ctx, "/repo", ListLocksOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(locks) != 1 {
		t.Fatalf("expected 1 lock, got %d", len(locks))
	}
	if locks[0].ID != lock.ID {
		t.Errorf("listed lock ID = %q, want %q", locks[0].ID, lock.ID)
	}
	if nextCursor != "" {
		t.Errorf("expected empty next_cursor, got %q", nextCursor)
	}
}

func TestFileLockStoreCreateConflict(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	if _, err := s.Create(ctx, "/repo", "same/path", "alice"); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	existing, err := s.Create(ctx, "/repo", "same/path", "bob")
	if !errors.Is(err, ErrLockExists) {
		t.Fatalf("expected ErrLockExists, got %v", err)
	}
	if existing.Owner.Name != "alice" {
		t.Errorf("returned existing lock owner = %q, want %q", existing.Owner.Name, "alice")
	}
}

func TestFileLockStoreCreateDifferentPaths(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	if _, err := s.Create(ctx, "/repo", "file1.txt", "alice"); err != nil {
		t.Fatalf("Create file1: %v", err)
	}
	if _, err := s.Create(ctx, "/repo", "file2.txt", "bob"); err != nil {
		t.Fatalf("Create file2: %v", err)
	}

	locks, _, err := s.List(ctx, "/repo", ListLocksOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(locks) != 2 {
		t.Fatalf("expected 2 locks, got %d", len(locks))
	}
}

func TestFileLockStoreListByPath(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	_, _ = s.Create(ctx, "/repo", "a.txt", "alice")
	_, _ = s.Create(ctx, "/repo", "b.txt", "bob")

	locks, _, err := s.List(ctx, "/repo", ListLocksOptions{Path: "a.txt"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(locks) != 1 {
		t.Fatalf("expected 1 lock, got %d", len(locks))
	}
	if locks[0].Path != "a.txt" {
		t.Errorf("Path = %q, want %q", locks[0].Path, "a.txt")
	}
}

func TestFileLockStoreListByID(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	lock1, _ := s.Create(ctx, "/repo", "a.txt", "alice")
	_, _ = s.Create(ctx, "/repo", "b.txt", "bob")

	locks, _, err := s.List(ctx, "/repo", ListLocksOptions{ID: lock1.ID})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(locks) != 1 {
		t.Fatalf("expected 1 lock, got %d", len(locks))
	}
	if locks[0].ID != lock1.ID {
		t.Errorf("ID = %q, want %q", locks[0].ID, lock1.ID)
	}
}

func TestFileLockStoreListPagination(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	for i := range 5 {
		path := "file" + string(rune('a'+i)) + ".txt"
		if _, err := s.Create(ctx, "/repo", path, "alice"); err != nil {
			t.Fatalf("Create %s: %v", path, err)
		}
	}

	// Get first 2.
	locks, cursor, err := s.List(ctx, "/repo", ListLocksOptions{Limit: 2})
	if err != nil {
		t.Fatalf("List page 1: %v", err)
	}
	if len(locks) != 2 {
		t.Fatalf("expected 2 locks, got %d", len(locks))
	}
	if cursor == "" {
		t.Fatal("expected non-empty cursor")
	}

	// Get next page using cursor.
	locks2, cursor2, err := s.List(ctx, "/repo", ListLocksOptions{Limit: 2, Cursor: cursor})
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if len(locks2) != 2 {
		t.Fatalf("expected 2 locks on page 2, got %d", len(locks2))
	}

	// Get last page.
	locks3, cursor3, err := s.List(ctx, "/repo", ListLocksOptions{Limit: 2, Cursor: cursor2})
	if err != nil {
		t.Fatalf("List page 3: %v", err)
	}
	if len(locks3) != 1 {
		t.Fatalf("expected 1 lock on page 3, got %d", len(locks3))
	}
	if cursor3 != "" {
		t.Errorf("expected empty cursor on last page, got %q", cursor3)
	}
}

func TestFileLockStoreUnlockOwner(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	lock, _ := s.Create(ctx, "/repo", "file.txt", "alice")

	unlocked, err := s.Unlock(ctx, "/repo", lock.ID, "alice", false)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if unlocked.ID != lock.ID {
		t.Errorf("unlocked ID = %q, want %q", unlocked.ID, lock.ID)
	}

	locks, _, _ := s.List(ctx, "/repo", ListLocksOptions{})
	if len(locks) != 0 {
		t.Fatalf("expected 0 locks after unlock, got %d", len(locks))
	}
}

func TestFileLockStoreUnlockNotOwner(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	lock, _ := s.Create(ctx, "/repo", "file.txt", "alice")

	_, err := s.Unlock(ctx, "/repo", lock.ID, "bob", false)
	if !errors.Is(err, ErrLockNotOwner) {
		t.Fatalf("expected ErrLockNotOwner, got %v", err)
	}
}

func TestFileLockStoreUnlockForce(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	lock, _ := s.Create(ctx, "/repo", "file.txt", "alice")

	unlocked, err := s.Unlock(ctx, "/repo", lock.ID, "bob", true)
	if err != nil {
		t.Fatalf("Unlock with force: %v", err)
	}
	if unlocked.ID != lock.ID {
		t.Errorf("unlocked ID = %q, want %q", unlocked.ID, lock.ID)
	}
}

func TestFileLockStoreUnlockNotFound(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)

	_, err := s.Unlock(t.Context(), "/repo", "nonexistent-id", "alice", false)
	if !errors.Is(err, ErrLockNotFound) {
		t.Fatalf("expected ErrLockNotFound, got %v", err)
	}
}

func TestFileLockStorePersistence(t *testing.T) {
	dir := t.TempDir()
	s1 := NewFileLockStore(dir)
	ctx := t.Context()

	lock, err := s1.Create(ctx, "/repo", "file.txt", "alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Create a new store pointing at the same directory.
	s2 := NewFileLockStore(dir)
	locks, _, err := s2.List(ctx, "/repo", ListLocksOptions{})
	if err != nil {
		t.Fatalf("List from new store: %v", err)
	}
	if len(locks) != 1 {
		t.Fatalf("expected 1 lock from new store, got %d", len(locks))
	}
	if locks[0].ID != lock.ID {
		t.Errorf("persisted lock ID = %q, want %q", locks[0].ID, lock.ID)
	}
}

func TestFileLockStoreConcurrentCreate(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := context.Background()

	var wg sync.WaitGroup
	results := make(chan error, 10)

	// Try to lock the same path concurrently.
	for range 10 {
		wg.Go(func() {
			_, err := s.Create(ctx, "/repo", "contested.txt", "user")
			results <- err
		})
	}
	wg.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLockExists):
			conflicts++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 success, got %d", successes)
	}
	if conflicts != 9 {
		t.Errorf("expected 9 conflicts, got %d", conflicts)
	}
}

func TestFileLockStoreSeparateStoresKeepAllLocks(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	const perStore = 40

	var wg sync.WaitGroup
	for store := range 2 {
		s := NewFileLockStore(dir)
		wg.Go(func() {
			for i := range perStore {
				if _, err := s.Create(ctx, "/repo", fmt.Sprintf("store-%d/file-%d.bin", store, i), "user"); err != nil {
					t.Errorf("Create: %v", err)
				}
			}
		})
	}
	wg.Wait()

	locks, _, err := NewFileLockStore(dir).List(ctx, "/repo", ListLocksOptions{Limit: maxLockLimit})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(locks) != 2*perStore {
		t.Fatalf("expected %d locks on disk, got %d", 2*perStore, len(locks))
	}
}

func TestFileLockStoreEndpointIsolation(t *testing.T) {
	dir := t.TempDir()
	s := NewFileLockStore(dir)
	ctx := t.Context()

	_, _ = s.Create(ctx, "/repo1", "file.txt", "alice")
	_, _ = s.Create(ctx, "/repo2", "file.txt", "bob")

	locks1, _, _ := s.List(ctx, "/repo1", ListLocksOptions{})
	locks2, _, _ := s.List(ctx, "/repo2", ListLocksOptions{})

	if len(locks1) != 1 || locks1[0].Owner.Name != "alice" {
		t.Errorf("repo1: expected 1 lock by alice, got %+v", locks1)
	}
	if len(locks2) != 1 || locks2[0].Owner.Name != "bob" {
		t.Errorf("repo2: expected 1 lock by bob, got %+v", locks2)
	}
}

// lockStoreWithFile returns a store whose /repo endpoint holds locks, written directly to its lock file in that order.
func lockStoreWithFile(tb testing.TB, locks []Lock) *FileLockStore {
	tb.Helper()
	s := NewFileLockStore(tb.TempDir())
	data, err := json.Marshal(locks)
	if err != nil {
		tb.Fatal(err)
	}
	if err := writeLockFile(s.lockFilePath("/repo"), data); err != nil {
		tb.Fatal(err)
	}
	return s
}

// lockIDs returns the IDs of locks in order.
func lockIDs(locks []Lock) []string {
	ids := make([]string, len(locks))
	for i, l := range locks {
		ids[i] = l.ID
	}
	return ids
}

func TestFileLockStoreListOptions(t *testing.T) {
	s := lockStoreWithFile(t, []Lock{
		{ID: "id-4", Path: "d.bin", LockedAt: "2026-01-01T00:00:03Z"},
		{ID: "id-1", Path: "a.bin", LockedAt: "2026-01-01T00:00:01Z"},
		{ID: "id-3", Path: "c.bin", LockedAt: "2026-01-01T00:00:02Z"},
		{ID: "id-2", Path: "b.bin", LockedAt: "2026-01-01T00:00:02Z"},
	})
	all := []string{"id-1", "id-2", "id-3", "id-4"}
	cursorAt := func(id, lockedAt string) string { return lockCursor(Lock{ID: id, LockedAt: lockedAt}) }
	tests := []struct {
		name       string
		opts       ListLocksOptions
		wantIDs    []string
		wantCursor string
	}{
		{name: "all, by time then ID", opts: ListLocksOptions{}, wantIDs: all},
		{
			name:       "first page",
			opts:       ListLocksOptions{Limit: 2},
			wantIDs:    []string{"id-1", "id-2"},
			wantCursor: cursorAt("id-2", "2026-01-01T00:00:02Z"),
		},
		{name: "last page", opts: ListLocksOptions{Limit: 2, Cursor: cursorAt("id-2", "2026-01-01T00:00:02Z")}, wantIDs: []string{"id-3", "id-4"}},
		{name: "cursor of a released lock", opts: ListLocksOptions{Cursor: cursorAt("id-2a", "2026-01-01T00:00:02Z")}, wantIDs: []string{"id-3", "id-4"}},
		{name: "cursor past the end", opts: ListLocksOptions{Cursor: cursorAt("id-9", "2026-01-01T00:00:09Z")}, wantIDs: []string{}},
		{name: "limit above maximum", opts: ListLocksOptions{Limit: maxLockLimit + 1}, wantIDs: all},
		{name: "path", opts: ListLocksOptions{Path: "b.bin"}, wantIDs: []string{"id-2"}},
		{name: "unknown path", opts: ListLocksOptions{Path: "e.bin"}, wantIDs: []string{}},
		{name: "path and its ID", opts: ListLocksOptions{Path: "b.bin", ID: "id-2"}, wantIDs: []string{"id-2"}},
		{name: "path and another ID", opts: ListLocksOptions{Path: "b.bin", ID: "id-3"}, wantIDs: []string{}},
		{name: "ID past its own cursor", opts: ListLocksOptions{ID: "id-3", Cursor: cursorAt("id-3", "2026-01-01T00:00:02Z")}, wantIDs: []string{}},
		{name: "ID with an earlier cursor", opts: ListLocksOptions{ID: "id-3", Cursor: cursorAt("id-1", "2026-01-01T00:00:01Z")}, wantIDs: []string{"id-3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locks, cursor, err := s.List(t.Context(), "/repo", tt.opts)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if got := lockIDs(locks); !slices.Equal(got, tt.wantIDs) {
				t.Errorf("IDs = %v, want %v", got, tt.wantIDs)
			}
			if cursor != tt.wantCursor {
				t.Errorf("cursor = %q, want %q", cursor, tt.wantCursor)
			}
		})
	}
}

func TestFileLockStoreListRejectsInvalidCursors(t *testing.T) {
	s := lockStoreWithFile(t, []Lock{{ID: "id-1", Path: "a.bin", LockedAt: "2026-01-01T00:00:01Z"}})
	for _, cursor := range []string{"id-1", "not base64!", base64.RawURLEncoding.EncodeToString([]byte("no separator"))} {
		if _, _, err := s.List(t.Context(), "/repo", ListLocksOptions{Cursor: cursor}); !errors.Is(err, ErrInvalidLockCursor) {
			t.Errorf("List with cursor %q: error = %v, want ErrInvalidLockCursor", cursor, err)
		}
	}
}

func TestFileLockStorePagingSurvivesReleasingTheCursorLock(t *testing.T) {
	s := NewFileLockStore(t.TempDir())
	ctx := t.Context()
	for i := range 5 {
		if _, err := s.Create(ctx, "/repo", fmt.Sprintf("file-%d.bin", i), "owner"); err != nil {
			t.Fatal(err)
		}
	}

	first, cursor, err := s.List(ctx, "/repo", ListLocksOptions{Limit: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Unlock(ctx, "/repo", first[1].ID, "owner", false); err != nil {
		t.Fatal(err)
	}
	seen := lockIDs(first)
	for cursor != "" {
		var page []Lock
		page, cursor, err = s.List(ctx, "/repo", ListLocksOptions{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		seen = append(seen, lockIDs(page)...)
	}

	if len(seen) != 5 || len(slices.Compact(slices.Sorted(slices.Values(seen)))) != 5 {
		t.Errorf("paging saw %v, want each of the 5 locks once", seen)
	}
}

func TestFileLockStoreListReturnsCopy(t *testing.T) {
	s := lockStoreWithFile(t, []Lock{
		{ID: "id-1", Path: "a.bin", LockedAt: "2026-01-01T00:00:01Z"},
		{ID: "id-2", Path: "b.bin", LockedAt: "2026-01-01T00:00:02Z"},
	})
	ctx := t.Context()

	locks, _, err := s.List(ctx, "/repo", ListLocksOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Unlock(ctx, "/repo", "id-1", "", true); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := s.Create(ctx, "/repo", "c.bin", "alice"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := lockIDs(locks); !slices.Equal(got, []string{"id-1", "id-2"}) {
		t.Errorf("earlier page changed to %v", got)
	}
}

func TestFileLockStoreSeesOtherStoreChanges(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	ours, theirs := NewFileLockStore(dir), NewFileLockStore(dir)
	paths := func() []string {
		t.Helper()
		locks, _, err := ours.List(ctx, "/repo", ListLocksOptions{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var paths []string
		for _, l := range locks {
			paths = append(paths, l.Path)
		}
		slices.Sort(paths)
		return paths
	}

	first, err := ours.Create(ctx, "/repo", "a.bin", "alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := theirs.Create(ctx, "/repo", "b.bin", "bob"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := paths(); !slices.Equal(got, []string{"a.bin", "b.bin"}) {
		t.Errorf("after the other store created a lock, paths = %v", got)
	}
	if _, err := theirs.Unlock(ctx, "/repo", first.ID, "bob", true); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := ours.Create(ctx, "/repo", "c.bin", "alice"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := paths(); !slices.Equal(got, []string{"b.bin", "c.bin"}) {
		t.Errorf("after the other store released a lock and this one created one, paths = %v", got)
	}
}

// benchmarkLockStore returns a store whose /repo endpoint holds count locks.
func benchmarkLockStore(b *testing.B, count int) *FileLockStore {
	b.Helper()
	locks := make([]Lock, count)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range locks {
		locks[i] = Lock{
			ID:       uuid.New().String(),
			Path:     fmt.Sprintf("assets/level-%d/texture-%d.uasset", i/100, i),
			LockedAt: start.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Owner:    LockOwner{Name: fmt.Sprintf("user-%d", i%20)},
		}
	}
	return lockStoreWithFile(b, locks)
}

func BenchmarkFileLockStore(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("List/%d", count), func(b *testing.B) {
			s := benchmarkLockStore(b, count)
			for b.Loop() {
				if _, _, err := s.List(b.Context(), "/repo", ListLocksOptions{}); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("VerifyWalk/%d", count), func(b *testing.B) {
			s := benchmarkLockStore(b, count)
			for b.Loop() {
				cursor := ""
				for {
					_, next, err := s.List(b.Context(), "/repo", ListLocksOptions{Cursor: cursor})
					if err != nil {
						b.Fatal(err)
					}
					if next == "" {
						break
					}
					cursor = next
				}
			}
		})
		b.Run(fmt.Sprintf("CreateUnlock/%d", count), func(b *testing.B) {
			s := benchmarkLockStore(b, count)
			for b.Loop() {
				lock, err := s.Create(b.Context(), "/repo", "new/file.uasset", "alice")
				if err != nil {
					b.Fatal(err)
				}
				if _, err := s.Unlock(b.Context(), "/repo", lock.ID, "alice", false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
