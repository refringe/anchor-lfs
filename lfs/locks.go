package lfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/refringe/anchor-lfs/internal/sanitise"
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

// FileLockStore persists locks as JSON files on the local filesystem.
// An in-memory cache avoids repeated disk reads; it is validated against
// the on-disk file's modification time and size on every access, so
// external modifications (manual edits, restores) are detected automatically.
//
// Write operations (Create, Unlock) load and rewrite the entire lock list,
// making this implementation O(n) per mutation. This is well-suited for
// typical LFS deployments with moderate lock counts (hundreds to low
// thousands per endpoint). Deployments expecting very high lock volumes
// should consider a database-backed LockStore implementation.
type FileLockStore struct {
	basePath string
	mutexes  sync.Map // map[string]*sync.RWMutex
	cache    sync.Map // map[string]cachedLocks — keyed by sanitised endpoint
}

// cachedLocks pairs a lock slice with the file metadata that was current
// when the cache was populated. A stat() comparison on read detects
// external modifications without re-reading the file contents.
type cachedLocks struct {
	locks   []Lock
	modTime time.Time
	size    int64
}

// NewFileLockStore creates a FileLockStore rooted at basePath.
func NewFileLockStore(basePath string) *FileLockStore {
	return &FileLockStore{basePath: basePath}
}

// endpointMutex returns the per-endpoint mutex, creating one if needed.
func (s *FileLockStore) endpointMutex(endpoint string) *sync.RWMutex {
	mu, _ := s.mutexes.LoadOrStore(sanitise.Endpoint(endpoint), &sync.RWMutex{})
	return mu.(*sync.RWMutex)
}

// lockFilePath returns the path to the JSON lock file for an endpoint.
func (s *FileLockStore) lockFilePath(endpoint string) string {
	return filepath.Join(s.basePath, "locks", sanitise.Endpoint(endpoint), "locks.json")
}

// loadLocks returns locks for the endpoint. The in-memory cache is
// validated against the on-disk file's modification time and size; if
// either differs (or the file was created/deleted externally) the cache
// is refreshed. Callers must hold at least an RLock on the endpoint mutex.
func (s *FileLockStore) loadLocks(endpoint string) ([]Lock, error) {
	key := sanitise.Endpoint(endpoint)
	path := s.lockFilePath(endpoint)

	info, statErr := os.Stat(path)

	if cached, ok := s.cache.Load(key); ok {
		c := cached.(cachedLocks) //nolint:forcetypeassert // type is guaranteed by cache store
		if statErr != nil {
			// File gone — cache is valid only if it was already empty.
			if errors.Is(statErr, os.ErrNotExist) && len(c.locks) == 0 {
				return nil, nil
			}
			// File disappeared but cache had locks — invalidate.
			if errors.Is(statErr, os.ErrNotExist) {
				s.cache.Delete(key)
				return nil, nil
			}
			return nil, fmt.Errorf("stat locks file: %w", statErr)
		}
		// File exists and metadata matches — cache hit.
		if c.modTime.Equal(info.ModTime()) && c.size == info.Size() {
			return copyLocks(c.locks), nil
		}
		// Metadata changed — fall through to re-read.
	}

	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat locks file: %w", statErr)
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from sanitised endpoint name
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading locks: %w", err)
	}
	var locks []Lock
	if err := json.Unmarshal(data, &locks); err != nil {
		return nil, fmt.Errorf("parsing locks: %w", err)
	}
	s.cache.Store(key, cachedLocks{
		locks:   copyLocks(locks),
		modTime: info.ModTime(),
		size:    info.Size(),
	})
	return locks, nil
}

// copyLocks returns a shallow copy of the lock slice so callers cannot
// mutate the cached data.
func copyLocks(src []Lock) []Lock {
	if src == nil {
		return nil
	}
	dst := make([]Lock, len(src))
	copy(dst, src)
	return dst
}

// saveLocks writes locks to disk atomically (temp file + fsync + rename).
func (s *FileLockStore) saveLocks(endpoint string, locks []Lock) error {
	path := s.lockFilePath(endpoint)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating lock directory: %w", err)
	}

	data, err := json.Marshal(locks)
	if err != nil {
		return fmt.Errorf("marshalling locks: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-locks-*")
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

	// Stat the written file so the cache entry matches the on-disk metadata.
	info, err := os.Stat(path)
	if err != nil {
		// The file was just written successfully, so a stat failure is unexpected. Delete the cache entry so the
		// next read re-fetches from disk, and log the anomaly for operator visibility.
		log.Warn().Err(err).Str("path", path).Msg("stat after writing lock file; cache invalidated")
		s.cache.Delete(sanitise.Endpoint(endpoint))
		return nil
	}
	s.cache.Store(sanitise.Endpoint(endpoint), cachedLocks{
		locks:   copyLocks(locks),
		modTime: info.ModTime(),
		size:    info.Size(),
	})
	return nil
}

// generateLockID creates a UUID v4 string. It uses hex.EncodeToString for clarity and to avoid manual hex formatting
// with fmt.Sprintf.
func generateLockID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating lock ID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4.
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10.
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// Create acquires a lock on the given path for the named owner.
func (s *FileLockStore) Create(ctx context.Context, endpoint, path, ownerName string) (Lock, error) {
	if err := ctx.Err(); err != nil {
		return Lock{}, err
	}
	mu := s.endpointMutex(endpoint)
	mu.Lock()
	defer mu.Unlock()

	locks, err := s.loadLocks(endpoint)
	if err != nil {
		return Lock{}, err
	}

	// Check for existing lock on the same path. Path comparison is
	// case-sensitive because lock paths are Git-relative file paths and
	// most filesystems (and the Git LFS spec) treat them as case-sensitive.
	// This differs from owner comparison (case-insensitive) because
	// usernames may vary in casing across auth providers.
	for _, l := range locks {
		if l.Path == path {
			return l, ErrLockExists
		}
	}

	id, err := generateLockID()
	if err != nil {
		return Lock{}, err
	}

	lock := Lock{
		ID:       id,
		Path:     path,
		LockedAt: time.Now().UTC().Format(time.RFC3339),
		Owner:    LockOwner{Name: ownerName},
	}

	locks = append(locks, lock)
	if err := s.saveLocks(endpoint, locks); err != nil {
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

	locks, err := s.loadLocks(endpoint)
	if err != nil {
		return nil, "", err
	}

	// Sort by creation time (stable order for pagination).
	sort.Slice(locks, func(i, j int) bool {
		if locks[i].LockedAt == locks[j].LockedAt {
			return locks[i].ID < locks[j].ID
		}
		return locks[i].LockedAt < locks[j].LockedAt
	})

	// Apply filters.
	var filtered []Lock
	for _, l := range locks {
		if opts.Path != "" && l.Path != opts.Path {
			continue
		}
		if opts.ID != "" && l.ID != opts.ID {
			continue
		}
		filtered = append(filtered, l)
	}

	// Apply cursor (skip past the lock with this ID).
	if opts.Cursor != "" {
		idx := -1
		for i, l := range filtered {
			if l.ID == opts.Cursor {
				idx = i
				break
			}
		}
		if idx >= 0 {
			filtered = filtered[idx+1:]
		}
	}

	// Apply limit.
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultLockLimit
	} else if limit > maxLockLimit {
		limit = maxLockLimit
	}

	// The cursor is set to the last item of the current page. On the next
	// request, List skips past the lock matching this cursor ID (see above),
	// so the next page starts at filtered[limit].
	var nextCursor string
	if len(filtered) > limit {
		nextCursor = filtered[limit-1].ID
		filtered = filtered[:limit]
	}

	return filtered, nextCursor, nil
}

// Unlock releases a lock by ID, checking ownership unless force is true.
func (s *FileLockStore) Unlock(ctx context.Context, endpoint, id, requester string, force bool) (Lock, error) {
	if err := ctx.Err(); err != nil {
		return Lock{}, err
	}
	mu := s.endpointMutex(endpoint)
	mu.Lock()
	defer mu.Unlock()

	locks, err := s.loadLocks(endpoint)
	if err != nil {
		return Lock{}, err
	}

	idx := -1
	for i, l := range locks {
		if l.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Lock{}, ErrLockNotFound
	}

	lock := locks[idx]
	// Case-insensitive: usernames may vary in casing across auth providers.
	if !force && !strings.EqualFold(lock.Owner.Name, requester) {
		return Lock{}, ErrLockNotOwner
	}

	locks = append(locks[:idx], locks[idx+1:]...)
	if err := s.saveLocks(endpoint, locks); err != nil {
		return Lock{}, err
	}
	return lock, nil
}
