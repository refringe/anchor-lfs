package lfs

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/refringe/anchor-lfs/internal/testutil"
	"github.com/refringe/anchor-lfs/storage"
)

// slowStoreDelay is how long each slowStore lookup takes.
const slowStoreDelay = 20 * time.Millisecond

// slowStore wraps a storage adapter, delaying each lookup by slowStoreDelay and counting how many run at once.
type slowStore struct {
	storage.Adapter
	mu       sync.Mutex
	calls    int
	inFlight int
	peak     int
}

func (s *slowStore) delay() {
	s.mu.Lock()
	s.calls++
	s.inFlight++
	s.peak = max(s.peak, s.inFlight)
	s.mu.Unlock()

	time.Sleep(slowStoreDelay)

	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()
}

func (s *slowStore) Exists(ctx context.Context, endpoint, oid string) (bool, error) {
	s.delay()
	return s.Adapter.Exists(ctx, endpoint, oid)
}

func (s *slowStore) Size(ctx context.Context, endpoint, oid string) (int64, error) {
	s.delay()
	return s.Adapter.Size(ctx, endpoint, oid)
}

// slowBatch returns a handler backed by a slowStore, the store, and count objects of which every third is stored.
func slowBatch(t *testing.T, count int) (*Handler, *slowStore, []Object) {
	t.Helper()
	h, local, _ := testHandler(t)
	store := &slowStore{Adapter: local}
	h.store = store

	objects := make([]Object, count)
	for i := range objects {
		content := fmt.Appendf(nil, "object %d", i)
		objects[i] = Object{OID: testutil.SHA256Hex(content), Size: int64(len(content))}
		if i%3 == 0 {
			if err := local.Put(context.Background(), h.endpoint.Path, objects[i].OID, bytes.NewReader(content), objects[i].Size); err != nil {
				t.Fatal(err)
			}
		}
	}
	return h, store, objects
}

func TestBatchLooksUpObjectsConcurrently(t *testing.T) {
	for _, operation := range []string{opDownload, opUpload} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, store, objects := slowBatch(t, 100)
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/org/repo/objects/batch", nil)

				start := time.Now()
				resp := h.processBatch(r, &BatchRequest{Operation: operation, Objects: objects}, "http://test")

				rounds := (len(objects) + batchConcurrency - 1) / batchConcurrency
				if elapsed, want := time.Since(start), time.Duration(rounds)*slowStoreDelay; elapsed != want {
					t.Errorf("batch took %v, want %v", elapsed, want)
				}
				if store.peak != batchConcurrency {
					t.Errorf("peak concurrent lookups = %d, want %d", store.peak, batchConcurrency)
				}
				if len(resp.Objects) != len(objects) {
					t.Fatalf("got %d objects, want %d", len(resp.Objects), len(objects))
				}
				for i, obj := range resp.Objects {
					if obj.OID != objects[i].OID {
						t.Fatalf("object %d has OID %s, want %s", i, obj.OID, objects[i].OID)
					}
					stored := i%3 == 0
					if wantAction := stored == (operation == opDownload); (obj.Actions[operation].Href != "") != wantAction {
						t.Errorf("object %d (stored %t): %s action present = %t, want %t", i, stored, operation, !wantAction, wantAction)
					}
				}
			})
		})
	}
}

func TestBatchStopsWhenClientGoesAway(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, store, objects := slowBatch(t, 100)
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(slowStoreDelay/2, cancel)
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/org/repo/objects/batch", nil)

		resp := h.processBatch(r, &BatchRequest{Operation: opUpload, Objects: objects}, "http://test")

		if len(resp.Objects) != batchConcurrency || store.calls != batchConcurrency {
			t.Errorf("got %d objects from %d lookups, want %d of each", len(resp.Objects), store.calls, batchConcurrency)
		}
	})
}
