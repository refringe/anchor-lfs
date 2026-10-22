package lfs

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/rs/zerolog/log"

	"github.com/refringe/anchor-lfs/internal/sanitise"
	"github.com/refringe/anchor-lfs/storage"
)

// Sentinel errors for lock operations.
var (
	ErrLockExists   = errors.New("lock already exists")
	ErrLockNotFound = errors.New("lock not found")
	ErrLockNotOwner = errors.New("not the lock owner")
)

// LockStore manages file locks for LFS endpoints.
type LockStore interface {
	// Create acquires a lock on the given path. Returns ErrLockExists if the
	// path is already locked (the existing lock is returned alongside the error).
	Create(ctx context.Context, endpoint, path, ownerName string) (Lock, error)

	// List returns locks matching the given options with cursor-based pagination.
	// The returned string is the next cursor (empty if no more results).
	List(ctx context.Context, endpoint string, opts ListLocksOptions) ([]Lock, string, error)

	// Unlock releases a lock. Returns ErrLockNotFound if the lock does not
	// exist, or ErrLockNotOwner if the requester is not the owner and force
	// is false.
	Unlock(ctx context.Context, endpoint, id, requester string, force bool) (Lock, error)
}

// ListLocksOptions configures lock listing queries.
type ListLocksOptions struct {
	Path    string
	ID      string
	Cursor  string
	Limit   int
	Refspec string // Accepted per spec; not used for filtering (auth is repo-level).
}

// Compile-time interface check.
var _ LockStore = (*FileLockStore)(nil)

const (
	defaultLockLimit = 100
	maxLockLimit     = 1000
)

// FileLockStore persists locks as one JSON file per endpoint, with writes serialised across goroutines and processes.
type FileLockStore struct {
	basePath string
	mutexes  sync.Map // map[string]*sync.RWMutex
	cache    sync.Map // map[string]cachedLocks, keyed by sanitised endpoint
}

// cachedLocks pairs an endpoint's indexed locks with the contents and metadata of the lock file they match.
type cachedLocks struct {
	set  *lockSet
	data []byte
	info os.FileInfo
}

// lockSet holds an endpoint's locks sorted by creation time then ID, indexed by ID and by path.
type lockSet struct {
	sorted []Lock
	byID   map[string]Lock
	byPath map[string]Lock
}

// newLockSet sorts and indexes locks.
func newLockSet(locks []Lock) *lockSet {
	slices.SortFunc(locks, compareLocks)
	set := &lockSet{sorted: locks, byID: make(map[string]Lock, len(locks)), byPath: make(map[string]Lock, len(locks))}
	for _, l := range locks {
		set.byID[l.ID] = l
		set.byPath[l.Path] = l
	}
	return set
}

// compareLocks orders locks by creation time, then ID.
func compareLocks(a, b Lock) int {
	return cmp.Or(strings.Compare(a.LockedAt, b.LockedAt), strings.Compare(a.ID, b.ID))
}

// add inserts lock in sorted position and indexes it.
func (set *lockSet) add(lock Lock) {
	i, _ := slices.BinarySearchFunc(set.sorted, lock, compareLocks)
	set.sorted = slices.Insert(set.sorted, i, lock)
	set.byID[lock.ID] = lock
	set.byPath[lock.Path] = lock
}

// remove deletes lock from the set.
func (set *lockSet) remove(lock Lock) {
	if i, found := slices.BinarySearchFunc(set.sorted, lock, compareLocks); found {
		set.sorted = slices.Delete(set.sorted, i, i+1)
	}
	delete(set.byID, lock.ID)
	if set.byPath[lock.Path].ID == lock.ID {
		delete(set.byPath, lock.Path)
	}
}

// list returns a copy of the page of locks matching opts and the cursor for the next page, or "" on the last page.
func (set *lockSet) list(opts ListLocksOptions) ([]Lock, string) {
	matches := set.sorted
	if opts.Path != "" || opts.ID != "" {
		matches = set.match(opts.Path, opts.ID)
	}

	// Skip past the lock with the cursor ID, or start from the beginning if it is not among the matches.
	if cursor, ok := set.byID[opts.Cursor]; ok {
		if i, found := slices.BinarySearchFunc(matches, cursor, compareLocks); found {
			matches = matches[i+1:]
		}
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLockLimit
	} else if limit > maxLockLimit {
		limit = maxLockLimit
	}
	if len(matches) <= limit {
		return slices.Clone(matches), ""
	}
	return slices.Clone(matches[:limit]), matches[limit-1].ID
}

// match returns the lock with the given path and ID, ignoring whichever is empty, as a slice of zero or one locks.
func (set *lockSet) match(path, id string) []Lock {
	lock, ok := set.byPath[path]
	if path == "" {
		lock, ok = set.byID[id]
	}
	if !ok || (id != "" && lock.ID != id) {
		return nil
	}
	return []Lock{lock}
}

// NewFileLockStore creates a FileLockStore rooted at basePath.
func NewFileLockStore(basePath string) *FileLockStore {
	return &FileLockStore{basePath: basePath}
}

// endpointMutex returns the per-endpoint mutex, creating it on first use.
func (s *FileLockStore) endpointMutex(endpoint string) *sync.RWMutex {
	mu, _ := s.mutexes.LoadOrStore(sanitise.Endpoint(endpoint), &sync.RWMutex{})
	return mu.(*sync.RWMutex)
}

// lockFilePath returns the path to the JSON lock file for an endpoint.
func (s *FileLockStore) lockFilePath(endpoint string) string {
	return filepath.Join(s.basePath, "locks", sanitise.Endpoint(endpoint), "locks.json")
}

// lockEndpoint takes the endpoint's write mutex and its locks.json.lock file lock, returning a function releasing both.
func (s *FileLockStore) lockEndpoint(endpoint string) (func(), error) {
	mu := s.endpointMutex(endpoint)
	mu.Lock()

	path := s.lockFilePath(endpoint) + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		mu.Unlock()
		return nil, fmt.Errorf("creating lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // path is built from the sanitised endpoint
	if err != nil {
		mu.Unlock()
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		mu.Unlock()
		return nil, fmt.Errorf("acquiring lock file: %w", err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
		mu.Unlock()
	}, nil
}

// cached returns the endpoint's cache entry, if there is one.
func (s *FileLockStore) cached(endpoint string) (cachedLocks, bool) {
	entry, ok := s.cache.Load(sanitise.Endpoint(endpoint))
	if !ok {
		return cachedLocks{}, false
	}
	return entry.(cachedLocks), true //nolint:forcetypeassert // type is guaranteed by cache store
}

// loadLocks returns the cached locks while the lock file's metadata is unchanged; callers hold the endpoint mutex.
func (s *FileLockStore) loadLocks(endpoint string) (*lockSet, error) {
	if c, ok := s.cached(endpoint); ok {
		info, err := os.Stat(s.lockFilePath(endpoint))
		if err == nil && os.SameFile(c.info, info) && c.info.ModTime().Equal(info.ModTime()) && c.info.Size() == info.Size() {
			return c.set, nil
		}
	}
	return s.readLocks(endpoint)
}

// readLocks reads the endpoint's lock file, reusing the cached locks when its contents are unchanged.
func (s *FileLockStore) readLocks(endpoint string) (*lockSet, error) {
	key := sanitise.Endpoint(endpoint)
	path := s.lockFilePath(endpoint)

	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		s.cache.Delete(key)
		return newLockSet(nil), nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat locks file: %w", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from sanitised endpoint name
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.cache.Delete(key)
			return newLockSet(nil), nil
		}
		return nil, fmt.Errorf("reading locks: %w", err)
	}
	if c, ok := s.cached(endpoint); ok && bytes.Equal(c.data, data) {
		s.cache.Store(key, cachedLocks{set: c.set, data: data, info: info})
		return c.set, nil
	}

	var locks []Lock
	if err := json.Unmarshal(data, &locks); err != nil {
		return nil, fmt.Errorf("parsing locks: %w", err)
	}
	set := newLockSet(locks)
	s.cache.Store(key, cachedLocks{set: set, data: data, info: info})
	return set, nil
}

// saveLocks writes set to the endpoint's lock file and caches it, or drops the endpoint's cache if the write fails.
func (s *FileLockStore) saveLocks(endpoint string, set *lockSet) error {
	key := sanitise.Endpoint(endpoint)
	path := s.lockFilePath(endpoint)

	data, err := json.Marshal(set.sorted)
	if err != nil {
		s.cache.Delete(key)
		return fmt.Errorf("marshalling locks: %w", err)
	}
	if err := writeLockFile(path, data); err != nil {
		s.cache.Delete(key)
		return err
	}

	// Stat the written file so the cache entry matches the on-disk metadata.
	info, err := os.Stat(path)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("stat after writing lock file; cache invalidated")
		s.cache.Delete(key)
		return nil
	}
	s.cache.Store(key, cachedLocks{set: set, data: data, info: info})
	return nil
}

// writeLockFile writes data to path atomically (temp file + fsync + rename).
func writeLockFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating lock directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), storage.TempFilePrefix+"locks-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath) // No-op after successful rename.
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing lock data: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing lock file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	closed = true

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming lock file: %w", err)
	}
	return nil
}

// Create acquires a lock on the given path for the named owner.
func (s *FileLockStore) Create(ctx context.Context, endpoint, path, ownerName string) (Lock, error) {
	if err := ctx.Err(); err != nil {
		return Lock{}, err
	}
	unlock, err := s.lockEndpoint(endpoint)
	if err != nil {
		return Lock{}, err
	}
	defer unlock()

	set, err := s.readLocks(endpoint)
	if err != nil {
		return Lock{}, err
	}

	if existing, ok := set.byPath[path]; ok {
		return existing, ErrLockExists
	}

	lock := Lock{
		ID:       uuid.New().String(),
		Path:     path,
		LockedAt: time.Now().UTC().Format(time.RFC3339),
		Owner:    LockOwner{Name: ownerName},
	}

	set.add(lock)
	if err := s.saveLocks(endpoint, set); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

// List returns locks matching the given options with cursor-based pagination.
func (s *FileLockStore) List(ctx context.Context, endpoint string, opts ListLocksOptions) ([]Lock, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	mu := s.endpointMutex(endpoint)
	mu.RLock()
	defer mu.RUnlock()

	set, err := s.loadLocks(endpoint)
	if err != nil {
		return nil, "", err
	}
	locks, nextCursor := set.list(opts)
	return locks, nextCursor, nil
}

// Unlock releases a lock by ID, checking ownership unless force is true.
func (s *FileLockStore) Unlock(ctx context.Context, endpoint, id, requester string, force bool) (Lock, error) {
	if err := ctx.Err(); err != nil {
		return Lock{}, err
	}
	unlock, err := s.lockEndpoint(endpoint)
	if err != nil {
		return Lock{}, err
	}
	defer unlock()

	set, err := s.readLocks(endpoint)
	if err != nil {
		return Lock{}, err
	}

	lock, ok := set.byID[id]
	if !ok {
		return Lock{}, ErrLockNotFound
	}
	if !force && !strings.EqualFold(lock.Owner.Name, requester) {
		return Lock{}, ErrLockNotOwner
	}

	set.remove(lock)
	if err := s.saveLocks(endpoint, set); err != nil {
		return Lock{}, err
	}
	return lock, nil
}
