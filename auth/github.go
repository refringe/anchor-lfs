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
	"sync/atomic"
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

	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64

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

// probe is the outcome of checking whether a token may read or write a repository's contents.
type probe uint8

const (
	probeUnchecked probe = iota
	probeAllowed
	probeDenied
)

// access is what GitHub reported about one token's access to one repository.
type access struct {
	authenticated bool
	username      string
	private       bool

	// The token owner's role on the repository.
	pull       bool
	push       bool
	maintainer bool

	// Whether the token itself may read and write the repository's contents.
	read  probe
	write probe
}

// result returns the authentication result for op.
func (a access) result(op Operation) Result {
	result := Result{Authenticated: a.authenticated, Username: a.username}
	switch op {
	case OperationDownload:
		result.Authorized = a.pull && (!a.private || a.read == probeAllowed)
	case OperationUpload:
		result.Authorized = a.push && a.write == probeAllowed
		result.Maintainer = result.Authorized && a.maintainer
	}
	return result
}

// needsProbe reports whether the result for op depends on a contents probe that has not run yet.
func (a access) needsProbe(op Operation) bool {
	switch op {
	case OperationDownload:
		return a.pull && a.private && a.read == probeUnchecked
	case OperationUpload:
		return a.push && a.write == probeUnchecked
	}
	return false
}

// withProbe returns a with the contents probe outcome for op recorded.
func (a access) withProbe(op Operation, outcome probe) access {
	switch op {
	case OperationDownload:
		a.read = outcome
	case OperationUpload:
		a.write = outcome
	}
	return a
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
	acc, err := g.lookup(ctx, endpoint, password, key)
	if err == nil && acc.needsProbe(op) {
		acc, err = g.share(ctx, key+"|"+string(op), func(ctx context.Context) (access, error) {
			return g.probeContents(ctx, endpoint, password, key, op, acc)
		})
	}
	if err != nil {
		return Result{}, err
	}
	return acc.result(op), nil
}

// lookup returns the token's cached access to the endpoint's repository, or asks GitHub for it.
func (g *GitHub) lookup(ctx context.Context, endpoint *config.Endpoint, token, key string) (access, error) {
	if cached, ok := g.cacheLookup(key); ok {
		g.cacheHits.Add(1)
		return cached, nil
	}
	g.cacheMisses.Add(1)
	return g.share(ctx, key, func(ctx context.Context) (access, error) {
		return g.fetchAccess(ctx, endpoint, token, key)
	})
}

// share runs fetch once for all concurrent callers with the same key, and keeps it running if the caller leaves.
func (g *GitHub) share(ctx context.Context, key string, fetch func(context.Context) (access, error)) (access, error) {
	shared := g.lookups.DoChan(key, func() (any, error) {
		return fetch(context.WithoutCancel(ctx))
	})
	select {
	case res := <-shared:
		if res.Err != nil {
			return access{}, res.Err
		}
		acc, _ := res.Val.(access)
		return acc, nil
	case <-ctx.Done():
		return access{}, fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
	}
}

// CacheStats returns how many authentications the cache answered and how many asked GitHub.
func (g *GitHub) CacheStats() (hits, misses uint64) {
	return g.cacheHits.Load(), g.cacheMisses.Load()
}

// client returns a GitHub API client that authenticates with token.
func (g *GitHub) client(token string) *github.Client {
	client := github.NewClient(g.httpClient).WithAuthToken(token)
	if g.baseURL != nil {
		client.BaseURL = g.baseURL
	}
	return client
}

// fetchAccess asks GitHub for the token owner's role on the endpoint's repository and caches any definitive answer.
func (g *GitHub) fetchAccess(ctx context.Context, endpoint *config.Endpoint, token, key string) (access, error) {
	client := g.client(token)
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
		private:       repo.GetPrivate(),
		pull:          perms["pull"],
		push:          perms["push"],
		maintainer:    perms["maintain"] || perms["admin"],
	}
	g.cacheStoreIfEnabled(key, granted)
	return granted, nil
}

// probeContents returns acc with whether the token may read or write the repository's contents for op, caching it.
func (g *GitHub) probeContents(ctx context.Context, endpoint *config.Endpoint, token, key string, op Operation, acc access) (access, error) {
	if cached, ok := g.cacheLookup(key); ok && !cached.needsProbe(op) {
		return cached, nil
	}
	client := g.client(token)
	var err error
	switch op {
	case OperationDownload:
		_, _, err = client.Repositories.ListCommits(ctx, endpoint.GitHubOwner, endpoint.GitHubRepo,
			&github.CommitsListOptions{ListOptions: github.ListOptions{PerPage: 1}})
	case OperationUpload:
		// Creating an empty blob always fails: with 422 if the token may write, or with 403 or 404 if it may not.
		_, _, err = client.Git.CreateBlob(ctx, endpoint.GitHubOwner, endpoint.GitHubRepo, &github.Blob{})
	}
	if isUnauthorized(err) {
		g.cacheStoreIfEnabled(key, access{})
		return access{}, nil
	}
	outcome, err := probeOutcome(err)
	if err != nil {
		return access{}, err
	}
	g.cacheRecordProbe(key, op, outcome)
	return acc.withProbe(op, outcome), nil
}

// isUnauthorized reports whether err is GitHub rejecting the token itself.
func isUnauthorized(err error) bool {
	respErr, ok := errors.AsType[*github.ErrorResponse](err)
	return ok && respErr.Response != nil && respErr.Response.StatusCode == http.StatusUnauthorized
}

// probeOutcome maps a probe error to allowed (none, 409, 422) or denied (403, 404), or returns GitHub's failure.
func probeOutcome(err error) (probe, error) {
	if err == nil {
		return probeAllowed, nil
	}
	if respErr, ok := errors.AsType[*github.ErrorResponse](err); ok && respErr.Response != nil {
		switch respErr.Response.StatusCode {
		case http.StatusConflict, http.StatusUnprocessableEntity:
			return probeAllowed, nil
		case http.StatusForbidden, http.StatusNotFound:
			return probeDenied, nil
		}
	}
	if _, err := classifyGitHubError(err); err != nil {
		return probeUnchecked, err
	}
	return probeDenied, nil
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

// cacheRecordProbe records a contents probe outcome on the access cached for key, if it is still cached.
func (g *GitHub) cacheRecordProbe(key string, op Operation, outcome probe) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if entry, ok := g.cache[key]; ok {
		entry.access = entry.access.withProbe(op, outcome)
		g.cache[key] = entry
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
