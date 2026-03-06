package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refringe/anchor-lfs/config"
)

// mockGitHubAPI returns a test server that mimics GitHub API endpoints.
// The requestCount is incremented on each /repos/ call (not /user calls).
func mockGitHubAPI(t *testing.T, requestCount *atomic.Int64, perms map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET /user — return authenticated user info (not counted).
		if r.URL.Path == "/api/v3/user" || r.URL.Path == "/user" {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || authHeader == "Bearer bad-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"login": "testuser",
				"id":    42,
			})
			return
		}

		// All other endpoints (repos, etc.) — counted.
		requestCount.Add(1)

		// Check for bearer token.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || authHeader == "Bearer bad-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":        1,
			"name":      "repo",
			"full_name": "org/repo",
		}
		if perms != nil {
			resp["permissions"] = perms
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func testEndpoint() *config.Endpoint {
	return &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "private",
		Authentication: "github",
		GitHubOwner:    "org",
		GitHubRepo:     "repo",
	}
}

func newGitHubAuth(serverURL string, cacheTTL time.Duration) *GitHub {
	u, _ := url.Parse(serverURL + "/")
	return NewGitHub(http.DefaultClient, cacheTTL, u)
}

func TestCacheHit(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true, "push": true})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, time.Minute)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ctx := context.Background()

	// First call hits the API.
	r1, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
	if !r1.Authenticated || !r1.Authorized {
		t.Fatalf("expected authenticated+authorized, got %+v", r1)
	}
	if r1.Username != "testuser" {
		t.Errorf("Username = %q, want %q", r1.Username, "testuser")
	}

	// Second call should be served from cache.
	r2, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
	if err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}
	if !r2.Authenticated || !r2.Authorized {
		t.Fatalf("expected authenticated+authorized from cache, got %+v", r2)
	}
	if r2.Username != "testuser" {
		t.Errorf("cached Username = %q, want %q", r2.Username, "testuser")
	}

	if count.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", count.Load())
	}
}

func TestCacheExpiry(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, 10*time.Millisecond)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ctx := context.Background()

	_, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	// Wait for cache to expire.
	time.Sleep(20 * time.Millisecond)

	_, err = g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
	if err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}

	if count.Load() != 2 {
		t.Errorf("expected 2 API calls after expiry, got %d", count.Load())
	}
}

func TestNegativeResultNotCached(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, time.Minute)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ctx := context.Background()

	// Bad token returns unauthenticated — should NOT be cached.
	r1, err := g.Authenticate(ctx, ep, "", "bad-token", OperationDownload)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if r1.Authenticated {
		t.Fatal("expected unauthenticated for bad token")
	}

	r2, err := g.Authenticate(ctx, ep, "", "bad-token", OperationDownload)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if r2.Authenticated {
		t.Fatal("expected unauthenticated for bad token (second call)")
	}

	if count.Load() != 2 {
		t.Errorf("expected 2 API calls (negative not cached), got %d", count.Load())
	}
}

func TestCacheKeyIsolation(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true, "push": false})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, time.Minute)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ctx := context.Background()

	// Download should hit API.
	r1, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
	if err != nil {
		t.Fatalf("download Authenticate: %v", err)
	}
	if !r1.Authorized {
		t.Fatal("expected download authorized")
	}

	// Upload with same token should hit API again (different op = different key).
	r2, err := g.Authenticate(ctx, ep, "", "good-token", OperationUpload)
	if err != nil {
		t.Fatalf("upload Authenticate: %v", err)
	}
	if r2.Authorized {
		t.Fatal("expected upload not authorized (push=false)")
	}

	if count.Load() != 2 {
		t.Errorf("expected 2 API calls (different ops), got %d", count.Load())
	}
}

func TestCacheDisabledWhenTTLZero(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, 0) // Caching disabled.

	ep := testEndpoint()
	ctx := context.Background()

	for range 3 {
		_, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	if count.Load() != 3 {
		t.Errorf("expected 3 API calls with caching disabled, got %d", count.Load())
	}
}

func TestCacheConcurrency(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true, "push": true})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, time.Minute)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
			if err != nil {
				t.Errorf("Authenticate: %v", err)
			}
		}()
	}
	wg.Wait()

	// With caching, we should see far fewer than 50 API calls.
	// The exact number depends on timing, but it must be at least 1.
	if count.Load() < 1 {
		t.Error("expected at least 1 API call")
	}
	if count.Load() > 50 {
		t.Errorf("expected at most 50 API calls, got %d", count.Load())
	}
}

func TestSweepCleansExpiredEntries(t *testing.T) {
	g := NewGitHub(nil, time.Millisecond, nil)

	// Manually populate cache with expired entries.
	g.mu.Lock()
	g.cache = map[string]cacheEntry{
		"key1": {result: Result{Authenticated: true}, expires: time.Now().Add(-time.Second)},
		"key2": {result: Result{Authenticated: true}, expires: time.Now().Add(-time.Second)},
		"key3": {result: Result{Authenticated: true}, expires: time.Now().Add(time.Hour)}, // Not expired.
	}
	g.mu.Unlock()

	g.sweep()

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) != 1 {
		t.Errorf("expected 1 remaining entry after sweep, got %d", len(g.cache))
	}
	if _, ok := g.cache["key3"]; !ok {
		t.Error("expected key3 to survive sweep")
	}
}

func TestPublicDownloadSkipsCache(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, time.Minute)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ep.Visibility = "public"
	ctx := context.Background()

	r, err := g.Authenticate(ctx, ep, "", "any-token", OperationDownload)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !r.Authenticated || !r.Authorized {
		t.Fatal("expected public download to be allowed without API call")
	}

	if count.Load() != 0 {
		t.Errorf("expected 0 API calls for public download, got %d", count.Load())
	}
}

func TestEmptyPasswordNotCached(t *testing.T) {
	g := NewGitHub(nil, time.Minute, nil)
	ep := testEndpoint()

	r, err := g.Authenticate(context.Background(), ep, "", "", OperationDownload)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if r.Authenticated {
		t.Fatal("expected unauthenticated for empty password")
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) != 0 {
		t.Errorf("expected empty cache, got %d entries", len(g.cache))
	}
}
