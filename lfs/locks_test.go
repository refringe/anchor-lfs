package lfs

import (
	"context"
	"errors"
	"sync"
	"testing"
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Create(ctx, "/repo", "contested.txt", "user")
			results <- err
		}()
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
