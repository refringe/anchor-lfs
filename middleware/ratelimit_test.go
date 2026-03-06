package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sethvargo/go-limiter/memorystore"
)

func TestRateLimitAllows(t *testing.T) {
	store, err := memorystore.New(&memorystore.Config{
		Tokens:   10,
		Interval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	called := false
	handler := RateLimit(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatal("expected handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRateLimitBlocks(t *testing.T) {
	store, err := memorystore.New(&memorystore.Config{
		Tokens:   1,
		Interval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := RateLimit(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should pass.
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}

	// Second request should be rate limited.
	req = httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", w.Code)
	}

	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}

	if w.Header().Get("Content-Type") != "application/vnd.git-lfs+json" {
		t.Fatalf("expected LFS content type, got %q", w.Header().Get("Content-Type"))
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["message"] != "rate limit exceeded" {
		t.Fatalf("expected rate limit message, got %q", body["message"])
	}
}

func TestClientIPFallback(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"

	ip := ClientIP(req)
	if ip == "" {
		t.Fatal("expected non-empty IP")
	}
}

func TestClientIPWithForwardedFor(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ip := ClientIP(req)
	// RightmostNonPrivate picks the rightmost non-private IP from the header.
	if ip != "8.8.8.8" {
		t.Fatalf("expected 8.8.8.8, got %q", ip)
	}
}
