package auth

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/refringe/anchor-lfs/config"
)

// mockGitHubAPI returns a test server that mimics GitHub API endpoints.
// The requestCount is incremented on each /repos/ call (not /user calls).
func mockGitHubAPI(t *testing.T, requestCount *atomic.Int64, perms map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GET /user returns the authenticated user and is not counted.
		if r.URL.Path == "/api/v3/user" || r.URL.Path == "/user" {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || authHeader == "Bearer bad-token" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.MarshalWrite(w, map[string]string{"message": "Bad credentials"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.MarshalWrite(w, map[string]any{
				"login": "testuser",
				"id":    42,
			})
			return
		}

		// The contents probes answer as for a token that may read and write, and are not counted.
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/blobs"):
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.MarshalWrite(w, map[string]string{"message": "Validation Failed"})
			return
		case strings.HasSuffix(r.URL.Path, "/commits"):
			_ = json.MarshalWrite(w, []any{})
			return
		}

		// Every other endpoint is counted.
		requestCount.Add(1)

		// Check for bearer token.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || authHeader == "Bearer bad-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.MarshalWrite(w, map[string]string{"message": "Bad credentials"})
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
		_ = json.MarshalWrite(w, resp)
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

// fakeGitHub is an in-memory GitHub API that counts requests and, when release is set, holds them until it is closed.
type fakeGitHub struct {
	perms   map[string]bool
	private bool

	// Contents probe statuses; zero answers 200 to the read probe and 422 to the write probe.
	readStatus  int
	writeStatus int

	release    chan struct{}
	repoCalls  atomic.Int64
	userCalls  atomic.Int64
	probeCalls atomic.Int64
}

func (f *fakeGitHub) RoundTrip(r *http.Request) (*http.Response, error) {
	isProbe := strings.HasSuffix(r.URL.Path, "/commits") || strings.HasSuffix(r.URL.Path, "/git/blobs")
	switch {
	case r.URL.Path == "/user":
		f.userCalls.Add(1)
	case isProbe:
		f.probeCalls.Add(1)
	default:
		f.repoCalls.Add(1)
	}
	if f.release != nil {
		select {
		case <-f.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}

	status, body := http.StatusOK, any(map[string]any{"id": 1, "full_name": "org/repo", "private": f.private, "permissions": f.perms})
	switch {
	case r.Header.Get("Authorization") != "Bearer good-token":
		status, body = http.StatusUnauthorized, map[string]string{"message": "Bad credentials"}
	case r.URL.Path == "/user":
		body = map[string]any{"login": "testuser", "id": 42}
	case strings.HasSuffix(r.URL.Path, "/commits"):
		status, body = cmp.Or(f.readStatus, http.StatusOK), []any{}
		if status != http.StatusOK {
			body = map[string]string{"message": http.StatusText(status)}
		}
	case strings.HasSuffix(r.URL.Path, "/git/blobs"):
		status, body = cmp.Or(f.writeStatus, http.StatusUnprocessableEntity), map[string]string{"message": "probe"}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    r,
	}, nil
}

// newFakeGitHubAuth returns a GitHub authenticator that sends its API calls to fake.
func newFakeGitHubAuth(fake *fakeGitHub, cacheTTL time.Duration) *GitHub {
	return NewGitHub(&http.Client{Transport: fake}, cacheTTL, &url.URL{Scheme: "https", Host: "api.github.test", Path: "/"})
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
	if hits, misses := g.CacheStats(); hits != 1 || misses != 1 {
		t.Errorf("CacheStats = %d hits, %d misses, want 1 and 1", hits, misses)
	}
}

func TestCacheExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const cacheTTL = 10 * time.Second
		fake := &fakeGitHub{perms: map[string]bool{"pull": true}}
		g := newFakeGitHubAuth(fake, cacheTTL)
		defer func() { _ = g.Close() }()
		authenticate := func() {
			t.Helper()
			r, err := g.Authenticate(t.Context(), testEndpoint(), "", "good-token", OperationUpload)
			if err != nil || !r.Authenticated {
				t.Fatalf("Authenticate = %+v, %v; want authenticated", r, err)
			}
		}

		authenticate()
		time.Sleep(cacheTTL - time.Second)
		authenticate()
		if got := fake.repoCalls.Load(); got != 1 {
			t.Errorf("GitHub calls within the TTL = %d, want 1", got)
		}
		time.Sleep(2 * time.Second)
		authenticate()
		if got := fake.repoCalls.Load(); got != 2 {
			t.Errorf("GitHub calls after the TTL = %d, want 2", got)
		}
	})
}

func TestInvalidTokenCachedBriefly(t *testing.T) {
	tests := []struct {
		name     string
		cacheTTL time.Duration
		window   time.Duration
	}{
		{name: "default TTL", cacheTTL: time.Minute, window: invalidTokenCacheTTL},
		{name: "shorter TTL", cacheTTL: 3 * time.Second, window: 3 * time.Second},
		{name: "caching disabled", cacheTTL: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fake := &fakeGitHub{}
				g := newFakeGitHubAuth(fake, tt.cacheTTL)
				defer func() { _ = g.Close() }()
				authenticate := func() {
					t.Helper()
					r, err := g.Authenticate(t.Context(), testEndpoint(), "", "bad-token", OperationUpload)
					if err != nil || r.Authenticated {
						t.Fatalf("Authenticate = %+v, %v; want unauthenticated", r, err)
					}
				}

				authenticate()
				if tt.window == 0 {
					authenticate()
					if got := fake.repoCalls.Load(); got != 2 {
						t.Errorf("GitHub calls with caching disabled = %d, want 2", got)
					}
					return
				}
				time.Sleep(tt.window - time.Second)
				authenticate()
				if got := fake.repoCalls.Load(); got != 1 {
					t.Errorf("GitHub calls within %v = %d, want 1", tt.window, got)
				}
				time.Sleep(2 * time.Second)
				authenticate()
				if got := fake.repoCalls.Load(); got != 2 {
					t.Errorf("GitHub calls after %v = %d, want 2", tt.window, got)
				}
			})
		})
	}
}

func TestCacheSharedAcrossOperationsNotEndpoints(t *testing.T) {
	var count atomic.Int64
	srv := mockGitHubAPI(t, &count, map[string]bool{"pull": true, "push": false})
	defer srv.Close()

	g := newGitHubAuth(srv.URL, time.Minute)
	defer func() { _ = g.Close() }()

	ep := testEndpoint()
	ctx := context.Background()

	r1, err := g.Authenticate(ctx, ep, "", "good-token", OperationDownload)
	if err != nil {
		t.Fatalf("download Authenticate: %v", err)
	}
	if !r1.Authorized {
		t.Fatal("expected download authorized")
	}

	r2, err := g.Authenticate(ctx, ep, "", "good-token", OperationUpload)
	if err != nil {
		t.Fatalf("upload Authenticate: %v", err)
	}
	if r2.Authorized || r2.Username != "testuser" {
		t.Fatalf("upload = %+v, want unauthorised testuser (push=false)", r2)
	}
	if got := count.Load(); got != 1 {
		t.Errorf("GitHub calls for both operations = %d, want 1", got)
	}

	other := testEndpoint()
	other.Path = "/org/other"
	if _, err := g.Authenticate(ctx, other, "", "good-token", OperationDownload); err != nil {
		t.Fatalf("other endpoint Authenticate: %v", err)
	}
	if got := count.Load(); got != 2 {
		t.Errorf("GitHub calls after a second endpoint = %d, want 2", got)
	}
}

func TestConcurrentLookupsShareOneCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeGitHub{perms: map[string]bool{"pull": true, "push": true}, release: make(chan struct{})}
		g := newFakeGitHubAuth(fake, time.Minute)
		defer func() { _ = g.Close() }()

		results := make([]Result, 20)
		var wg sync.WaitGroup
		for i := range results {
			op := OperationDownload
			if i%2 == 1 {
				op = OperationUpload
			}
			wg.Go(func() {
				r, err := g.Authenticate(t.Context(), testEndpoint(), "", "good-token", op)
				if err != nil {
					t.Errorf("Authenticate: %v", err)
				}
				results[i] = r
			})
		}
		synctest.Wait()
		close(fake.release)
		wg.Wait()

		for i, r := range results {
			if !r.Authorized || r.Username != "testuser" {
				t.Errorf("result %d = %+v, want authorised testuser", i, r)
			}
		}
		if repo, user, probes := fake.repoCalls.Load(), fake.userCalls.Load(), fake.probeCalls.Load(); repo != 1 || user != 1 || probes != 1 {
			t.Errorf("GitHub calls = %d repository, %d user and %d probe, want 1 of each", repo, user, probes)
		}
	})
}

func TestLookupSurvivesFirstCallerLeaving(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := &fakeGitHub{perms: map[string]bool{"pull": true}, release: make(chan struct{})}
		g := newFakeGitHubAuth(fake, time.Minute)
		defer func() { _ = g.Close() }()

		firstCtx, leave := context.WithCancel(t.Context())
		var firstErr error
		var wg sync.WaitGroup
		wg.Go(func() {
			_, firstErr = g.Authenticate(firstCtx, testEndpoint(), "", "good-token", OperationDownload)
		})
		synctest.Wait()
		var second Result
		var secondErr error
		wg.Go(func() {
			second, secondErr = g.Authenticate(t.Context(), testEndpoint(), "", "good-token", OperationDownload)
		})
		synctest.Wait()

		leave()
		synctest.Wait()
		close(fake.release)
		wg.Wait()

		if !errors.Is(firstErr, context.Canceled) || !errors.Is(firstErr, ErrUnavailable) {
			t.Errorf("first caller error = %v, want ErrUnavailable wrapping context.Canceled", firstErr)
		}
		if secondErr != nil || !second.Authorized {
			t.Errorf("second caller = %+v, %v; want authorised", second, secondErr)
		}
		if _, err := g.Authenticate(t.Context(), testEndpoint(), "", "good-token", OperationDownload); err != nil {
			t.Fatalf("cached Authenticate: %v", err)
		}
		if got := fake.repoCalls.Load(); got != 1 {
			t.Errorf("GitHub repository calls = %d, want 1", got)
		}
	})
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
	if hits, misses := g.CacheStats(); hits != 0 || misses != 3 {
		t.Errorf("CacheStats = %d hits, %d misses, want 0 and 3", hits, misses)
	}
}

func TestSweepCleansExpiredEntries(t *testing.T) {
	g := NewGitHub(nil, time.Millisecond, nil)

	// Manually populate cache with expired entries.
	g.mu.Lock()
	g.cache = map[string]cacheEntry{
		"key1": {access: access{authenticated: true}, expires: time.Now().Add(-time.Second)},
		"key2": {access: access{authenticated: true}, expires: time.Now().Add(-time.Second)},
		"key3": {access: access{authenticated: true}, expires: time.Now().Add(time.Hour)}, // Not expired.
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
	if hits, misses := g.CacheStats(); hits != 0 || misses != 0 {
		t.Errorf("CacheStats = %d hits, %d misses, want 0 and 0", hits, misses)
	}
}

func TestMaintainerFromRepositoryPermissions(t *testing.T) {
	tests := []struct {
		name  string
		perms map[string]bool
		want  bool
	}{
		{"push only", map[string]bool{"pull": true, "push": true}, false},
		{"maintain", map[string]bool{"pull": true, "push": true, "maintain": true}, true},
		{"admin", map[string]bool{"pull": true, "push": true, "admin": true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count atomic.Int64
			srv := mockGitHubAPI(t, &count, tt.perms)
			defer srv.Close()
			g := newGitHubAuth(srv.URL, 0)
			defer func() { _ = g.Close() }()

			r, err := g.Authenticate(context.Background(), testEndpoint(), "", "good-token", OperationUpload)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if !r.Authorized || r.Maintainer != tt.want {
				t.Errorf("Authorized = %t, Maintainer = %t; want true, %t", r.Authorized, r.Maintainer, tt.want)
			}
		})
	}
}

func TestContentsProbes(t *testing.T) {
	admin := map[string]bool{"pull": true, "push": true, "admin": true}
	tests := []struct {
		name            string
		perms           map[string]bool
		private         bool
		readStatus      int
		writeStatus     int
		op              Operation
		want            Result
		wantProbes      int64
		wantUnavailable bool
		wantRateLimited bool
	}{
		{name: "upload with write access", perms: admin, op: OperationUpload,
			want: Result{Authenticated: true, Authorized: true, Username: "testuser", Maintainer: true}, wantProbes: 1},
		{name: "upload with read-only token", perms: admin, writeStatus: http.StatusForbidden, op: OperationUpload,
			want: Result{Authenticated: true, Username: "testuser"}, wantProbes: 1},
		{name: "upload with token for another repository", perms: admin, writeStatus: http.StatusNotFound, op: OperationUpload,
			want: Result{Authenticated: true, Username: "testuser"}, wantProbes: 1},
		{name: "upload without push role", perms: map[string]bool{"pull": true}, op: OperationUpload,
			want: Result{Authenticated: true, Username: "testuser"}},
		{name: "private download with contents access", perms: admin, private: true, op: OperationDownload,
			want: Result{Authenticated: true, Authorized: true, Username: "testuser"}, wantProbes: 1},
		{name: "private download of empty repository", perms: admin, private: true, readStatus: http.StatusConflict, op: OperationDownload,
			want: Result{Authenticated: true, Authorized: true, Username: "testuser"}, wantProbes: 1},
		{name: "private download without contents access", perms: admin, private: true, readStatus: http.StatusForbidden, op: OperationDownload,
			want: Result{Authenticated: true, Username: "testuser"}, wantProbes: 1},
		{name: "public repository download", perms: map[string]bool{"pull": true}, op: OperationDownload,
			want: Result{Authenticated: true, Authorized: true, Username: "testuser"}},
		{name: "probe server error", perms: admin, writeStatus: http.StatusBadGateway, op: OperationUpload,
			wantProbes: 2, wantUnavailable: true},
		{name: "probe rate limited", perms: admin, writeStatus: http.StatusTooManyRequests, op: OperationUpload,
			wantProbes: 2, wantRateLimited: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeGitHub{perms: tt.perms, private: tt.private, readStatus: tt.readStatus, writeStatus: tt.writeStatus}
			g := newFakeGitHubAuth(fake, time.Minute)
			defer func() { _ = g.Close() }()

			for range 2 {
				result, err := g.Authenticate(t.Context(), testEndpoint(), "", "good-token", tt.op)
				_, isRateLimited := errors.AsType[*RateLimitedError](err)
				switch {
				case tt.wantUnavailable:
					if !errors.Is(err, ErrUnavailable) {
						t.Fatalf("error = %v, want ErrUnavailable", err)
					}
				case tt.wantRateLimited:
					if !isRateLimited {
						t.Fatalf("error = %v, want RateLimitedError", err)
					}
				case err != nil:
					t.Fatalf("Authenticate: %v", err)
				}
				if result != tt.want {
					t.Errorf("result = %+v, want %+v", result, tt.want)
				}
			}
			if got := fake.probeCalls.Load(); got != tt.wantProbes {
				t.Errorf("probe calls = %d, want %d", got, tt.wantProbes)
			}
		})
	}
}

func TestContentsProbesShareOneLookup(t *testing.T) {
	fake := &fakeGitHub{perms: map[string]bool{"pull": true, "push": true}, private: true}
	g := newFakeGitHubAuth(fake, time.Minute)
	defer func() { _ = g.Close() }()

	for _, op := range []Operation{OperationUpload, OperationDownload, OperationUpload, OperationDownload} {
		if r, err := g.Authenticate(t.Context(), testEndpoint(), "", "good-token", op); err != nil || !r.Authorized {
			t.Fatalf("Authenticate(%s) = %+v, %v; want authorised", op, r, err)
		}
	}
	if repo, user, probes := fake.repoCalls.Load(), fake.userCalls.Load(), fake.probeCalls.Load(); repo != 1 || user != 1 || probes != 2 {
		t.Errorf("GitHub calls = %d repository, %d user and %d probe, want 1, 1 and 2", repo, user, probes)
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

func TestGitHubAPIErrors(t *testing.T) {
	reset := strconv.FormatInt(time.Now().Add(2*time.Minute).Unix(), 10)
	distantReset := strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10)
	tests := []struct {
		name            string
		status          int
		header          map[string]string
		body            map[string]string
		want            Result
		wantRetryAfter  time.Duration
		wantUnavailable bool
		wantCached      bool
	}{
		{name: "bad credentials", status: http.StatusUnauthorized, body: map[string]string{"message": "Bad credentials"}, wantCached: true},
		{name: "repository not visible", status: http.StatusNotFound, body: map[string]string{"message": "Not Found"}, want: Result{Authenticated: true}, wantCached: true},
		{
			name:       "SSO not authorised",
			status:     http.StatusForbidden,
			header:     map[string]string{"X-GitHub-SSO": "required; url=https://github.com/orgs/org/sso"},
			body:       map[string]string{"message": "Resource protected by SAML enforcement."},
			want:       Result{Authenticated: true},
			wantCached: true,
		},
		{
			name:           "primary rate limit",
			status:         http.StatusForbidden,
			header:         map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset},
			body:           map[string]string{"message": "API rate limit exceeded"},
			wantRetryAfter: 2 * time.Minute,
		},
		{
			name:           "distant reset capped",
			status:         http.StatusForbidden,
			header:         map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": distantReset},
			body:           map[string]string{"message": "API rate limit exceeded"},
			wantRetryAfter: maxRetryAfter,
		},
		{
			name:           "secondary rate limit",
			status:         http.StatusForbidden,
			header:         map[string]string{"Retry-After": "30"},
			body:           map[string]string{"message": "You have exceeded a secondary rate limit.", "documentation_url": "https://docs.github.com/rest/overview/rate-limits-for-the-rest-api#about-secondary-rate-limits"},
			wantRetryAfter: 30 * time.Second,
		},
		{name: "too many requests", status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "45"}, wantRetryAfter: 45 * time.Second},
		{name: "too many requests without hint", status: http.StatusTooManyRequests, wantRetryAfter: defaultRetryAfter},
		{name: "server error", status: http.StatusInternalServerError, wantUnavailable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				for name, value := range tt.header {
					w.Header().Set(name, value)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_ = json.MarshalWrite(w, tt.body)
			}))
			defer srv.Close()
			g := newGitHubAuth(srv.URL, time.Minute)
			defer func() { _ = g.Close() }()

			for range 2 {
				result, err := g.Authenticate(context.Background(), testEndpoint(), "", "token", OperationDownload)
				if result != tt.want {
					t.Errorf("result = %+v, want %+v", result, tt.want)
				}
				rateErr, isRateLimited := errors.AsType[*RateLimitedError](err)
				switch {
				case tt.wantRetryAfter > 0:
					if !isRateLimited {
						t.Fatalf("error = %v, want RateLimitedError", err)
					}
					if diff := rateErr.RetryAfter - tt.wantRetryAfter; diff > time.Second || diff < -5*time.Second {
						t.Errorf("RetryAfter = %v, want about %v", rateErr.RetryAfter, tt.wantRetryAfter)
					}
				case tt.wantUnavailable:
					if !errors.Is(err, ErrUnavailable) {
						t.Fatalf("error = %v, want ErrUnavailable", err)
					}
				case err != nil:
					t.Fatalf("Authenticate: %v", err)
				}
			}

			wantCalls := int64(2)
			if tt.wantCached {
				wantCalls = 1
			}
			if got := calls.Load(); got != wantCalls {
				t.Errorf("GitHub API calls = %d, want %d", got, wantCalls)
			}
		})
	}
}
