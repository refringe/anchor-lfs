package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/refringe/anchor-lfs/config"
)

// cacheHMACKey is a random key generated at process start used to derive cache keys via HMAC-SHA256. Using HMAC with a
// per-process key ensures token-derived cache keys are not predictable across restarts.
var cacheHMACKey = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("auth: failed to generate cache HMAC key: " + err.Error())
	}
	return key
}()

// Compile-time interface check.
var _ Authenticator = (*GitHub)(nil)

// GitHub authenticates users by validating their token against the GitHub API.
// Successful authentication results are cached to reduce API calls.
type GitHub struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	baseURL    *url.URL

	mu       sync.Mutex
	cache    map[string]cacheEntry
	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewGitHub creates a GitHub authenticator. The httpClient is used for GitHub
// API calls; sharing a single client across endpoints allows connection pooling.
// If nil, http.DefaultClient is used. The cacheTTL controls how long successful
// auth results are cached; a zero value disables caching entirely. The baseURL
// overrides the GitHub API base URL for GitHub Enterprise deployments; pass nil
// to use the default (https://api.github.com/).
func NewGitHub(httpClient *http.Client, cacheTTL time.Duration, baseURL *url.URL) *GitHub {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &GitHub{
		httpClient: httpClient,
		cacheTTL:   cacheTTL,
		baseURL:    baseURL,
	}
}

type cacheEntry struct {
	result  Result
	expires time.Time
}

// Authenticate validates the user's GitHub token against the configured
// repository. The username from Basic Auth is not verified — GitHub tokens
// are self-authenticating, and Git LFS clients send it only as a hint.
func (g *GitHub) Authenticate(ctx context.Context, endpoint *config.Endpoint, _ string, password string, op Operation) (Result, error) {
	if endpoint.IsPublic() && op == OperationDownload {
		return Result{Authenticated: true, Authorized: true}, nil
	}

	if password == "" {
		return Result{}, nil
	}

	// Cache lookup.
	key := cacheKey(password, endpoint.Path, op)
	if g.cacheTTL > 0 {
		if result, ok := g.cacheLookup(key); ok {
			return result, nil
		}
	}

	client := github.NewClient(g.httpClient).WithAuthToken(password)
	if g.baseURL != nil {
		client.BaseURL = g.baseURL
	}

	repo, _, err := client.Repositories.Get(ctx, endpoint.GitHubOwner, endpoint.GitHubRepo)
	if err != nil {
		if ghErr, ok := errors.AsType[*github.ErrorResponse](err); ok && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusUnauthorized {
			return Result{Authenticated: false}, nil // NOT cached.
		}
		return Result{}, fmt.Errorf("github API: %w", err) // NOT cached.
	}

	perms := repo.GetPermissions()
	if perms == nil {
		// No permissions object — the user is authenticated but we cannot
		// determine authorization. Return without caching so the next
		// request retries rather than locking in an ambiguous result.
		return Result{Authenticated: true}, nil
	}

	// Fetch the authenticated user's login for lock ownership.
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return Result{}, fmt.Errorf("github API (user): %w", err) // NOT cached.
	}
	username := user.GetLogin()

	var result Result
	switch op {
	case OperationDownload:
		result = Result{Authenticated: true, Authorized: perms["pull"], Username: username}
	case OperationUpload:
		result = Result{Authenticated: true, Authorized: perms["push"], Username: username}
	default:
		result = Result{Authenticated: true, Username: username}
	}

	g.cacheStoreIfEnabled(key, result)
	return result, nil
}

// Close shuts down the background cache sweeper. It is safe to call multiple
// times or if the sweeper was never started.
func (g *GitHub) Close() error {
	g.mu.Lock()
	ch := g.stopCh
	g.mu.Unlock()
	if ch != nil {
		g.stopOnce.Do(func() { close(ch) })
	}
	return nil
}

func (g *GitHub) cacheLookup(key string) (Result, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.cache[key]
	if !ok {
		return Result{}, false
	}
	if time.Now().After(entry.expires) {
		delete(g.cache, key)
		return Result{}, false
	}
	return entry.result, true
}

func (g *GitHub) cacheStoreIfEnabled(key string, result Result) {
	if g.cacheTTL <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cache == nil {
		g.cache = make(map[string]cacheEntry)
		g.startSweeperLocked()
	}
	g.cache[key] = cacheEntry{
		result:  result,
		expires: time.Now().Add(g.cacheTTL),
	}
}

// minSweepInterval is the minimum interval between cache sweeps to prevent
// excessive CPU usage when cacheTTL is very small.
const minSweepInterval = time.Second

// startSweeperLocked starts the background goroutine that periodically removes
// expired cache entries. Must be called with g.mu held.
func (g *GitHub) startSweeperLocked() {
	g.stopCh = make(chan struct{})
	go func() {
		interval := g.cacheTTL / 2
		if interval < minSweepInterval {
			interval = minSweepInterval
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				g.sweep()
			case <-g.stopCh:
				return
			}
		}
	}()
}

func (g *GitHub) sweep() {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.cache {
		if now.After(v.expires) {
			delete(g.cache, k)
		}
	}
}

// cacheKey builds a cache key from the token, endpoint path, and operation. The token is run through HMAC-SHA256 with a
// per-process random key so raw credentials are not stored in memory and derived keys are not predictable.
func cacheKey(token, endpointPath string, op Operation) string {
	mac := hmac.New(sha256.New, cacheHMACKey)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil)) + "|" + endpointPath + "|" + string(op)
}
