package auth

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/refringe/anchor-lfs/config"
	"golang.org/x/sync/singleflight"
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

// GitHub authenticates tokens against the GitHub API, caching each token's access per endpoint and sharing lookups.
type GitHub struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	baseURL    *url.URL
	lookups    singleflight.Group

	mu       sync.Mutex
	cache    map[string]cacheEntry
	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewGitHub returns an authenticator for baseURL (nil for api.github.com) caching results for cacheTTL (0 disables).
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

// invalidTokenCacheTTL caps how long a token GitHub rejects as invalid stays cached.
const invalidTokenCacheTTL = 10 * time.Second

// access is what GitHub reported about one token's access to one repository.
type access struct {
	authenticated bool
	username      string
	pull          bool
	push          bool
	maintainer    bool
}

// result returns the authentication result for op.
func (a access) result(op Operation) Result {
	result := Result{Authenticated: a.authenticated, Username: a.username, Maintainer: a.maintainer}
	switch op {
	case OperationDownload:
		result.Authorized = a.pull
	case OperationUpload:
		result.Authorized = a.push
	}
	return result
}

type cacheEntry struct {
	access  access
	expires time.Time
}

// Authenticate checks the token's access to the endpoint's repository, ignoring the Basic Auth username.
func (g *GitHub) Authenticate(ctx context.Context, endpoint *config.Endpoint, _ string, password string, op Operation) (Result, error) {
	if endpoint.IsPublic() && op == OperationDownload {
		return Result{Authenticated: true, Authorized: true}, nil
	}

	if password == "" {
		return Result{}, nil
	}

	key := cacheKey(password, endpoint.Path)
	if cached, ok := g.cacheLookup(key); ok {
		return cached.result(op), nil
	}

	lookup := g.lookups.DoChan(key, func() (any, error) {
		return g.fetchAccess(context.WithoutCancel(ctx), endpoint, password, key)
	})
	select {
	case res := <-lookup:
		if res.Err != nil {
			return Result{}, res.Err
		}
		fetched, _ := res.Val.(access)
		return fetched.result(op), nil
	case <-ctx.Done():
		return Result{}, fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
	}
}

// fetchAccess asks GitHub for the token's access to the endpoint's repository and caches any definitive answer.
func (g *GitHub) fetchAccess(ctx context.Context, endpoint *config.Endpoint, token, key string) (access, error) {
	client := github.NewClient(g.httpClient).WithAuthToken(token)
	if g.baseURL != nil {
		client.BaseURL = g.baseURL
	}

	repo, _, err := client.Repositories.Get(ctx, endpoint.GitHubOwner, endpoint.GitHubRepo)
	if err != nil {
		denied, err := classifyGitHubError(err)
		if err == nil {
			g.cacheStoreIfEnabled(key, denied)
		}
		return denied, err
	}

	perms := repo.GetPermissions()
	if perms == nil {
		// Without a permissions object the token is valid but its access is unknown, so the answer is not cached.
		return access{authenticated: true}, nil
	}

	// Fetch the authenticated user's login for lock ownership.
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return classifyGitHubError(err) // NOT cached.
	}

	granted := access{
		authenticated: true,
		username:      user.GetLogin(),
		pull:          perms["pull"],
		push:          perms["push"],
		maintainer:    perms["maintain"] || perms["admin"],
	}
	g.cacheStoreIfEnabled(key, granted)
	return granted, nil
}

// defaultRetryAfter is the wait reported when GitHub rate limits a request without saying when to retry, and
// maxRetryAfter caps the wait GitHub asks for.
const (
	defaultRetryAfter = time.Minute
	maxRetryAfter     = time.Hour
)

// classifyGitHubError maps a GitHub API error to a definitive access, a *RateLimitedError, or an ErrUnavailable error.
func classifyGitHubError(err error) (access, error) {
	if rateErr, ok := errors.AsType[*github.RateLimitError](err); ok {
		return access{}, rateLimited(untilReset(rateErr.Rate.Reset.Time))
	}
	if abuseErr, ok := errors.AsType[*github.AbuseRateLimitError](err); ok {
		return access{}, rateLimited(cmp.Or(abuseErr.GetRetryAfter(), defaultRetryAfter))
	}
	if respErr, ok := errors.AsType[*github.ErrorResponse](err); ok && respErr.Response != nil {
		switch respErr.Response.StatusCode {
		case http.StatusUnauthorized:
			return access{}, nil
		case http.StatusForbidden, http.StatusNotFound:
			return access{authenticated: true}, nil
		case http.StatusTooManyRequests:
			return access{}, rateLimited(retryAfter(respErr.Response.Header))
		}
	}
	return access{}, fmt.Errorf("%w: github API: %w", ErrUnavailable, err)
}

// rateLimited returns a RateLimitedError asking the caller to wait, at most maxRetryAfter.
func rateLimited(wait time.Duration) *RateLimitedError {
	return &RateLimitedError{RetryAfter: min(wait, maxRetryAfter)}
}

// retryAfter reads how long to wait from the Retry-After or X-RateLimit-Reset header of a rate-limited response.
func retryAfter(header http.Header) time.Duration {
	if seconds, err := strconv.Atoi(header.Get("Retry-After")); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if reset, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		return untilReset(time.Unix(reset, 0))
	}
	return defaultRetryAfter
}

// untilReset returns the wait until a rate limit resets, at least one second, or defaultRetryAfter if reset is unknown.
func untilReset(reset time.Time) time.Duration {
	if reset.IsZero() {
		return defaultRetryAfter
	}
	return max(time.Until(reset), time.Second)
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

func (g *GitHub) cacheLookup(key string) (access, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.cache[key]
	if !ok {
		return access{}, false
	}
	if time.Now().After(entry.expires) {
		delete(g.cache, key)
		return access{}, false
	}
	return entry.access, true
}

// cacheStoreIfEnabled caches acc for the cache TTL, or for at most invalidTokenCacheTTL when the token is invalid.
func (g *GitHub) cacheStoreIfEnabled(key string, acc access) {
	ttl := g.cacheTTL
	if !acc.authenticated {
		ttl = min(ttl, invalidTokenCacheTTL)
	}
	if ttl <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cache == nil {
		g.cache = make(map[string]cacheEntry)
		g.startSweeperLocked()
	}
	g.cache[key] = cacheEntry{
		access:  acc,
		expires: time.Now().Add(ttl),
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
		interval := max(g.cacheTTL/2, minSweepInterval)
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

// cacheKey builds a cache key from the endpoint path and an HMAC-SHA256 of the token under a per-process random key.
func cacheKey(token, endpointPath string) string {
	mac := hmac.New(sha256.New, cacheHMACKey)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil)) + "|" + endpointPath
}
