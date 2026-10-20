package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/sethvargo/go-limiter/memorystore"

	"github.com/refringe/anchor-lfs/config"
)

func TestProxyTrustHandler(t *testing.T) {
	tests := []struct {
		name        string
		trusted     []string
		remoteAddr  string
		forwarded   string
		wantIP      string
		wantHeaders bool
	}{
		{name: "direct client", trusted: config.DefaultTrustedProxies, remoteAddr: "203.0.113.7:4000", wantIP: "203.0.113.7"},
		{name: "spoofed header from public peer", trusted: config.DefaultTrustedProxies, remoteAddr: "203.0.113.7:4000", forwarded: "8.8.8.8", wantIP: "203.0.113.7"},
		{name: "trusted proxy", trusted: config.DefaultTrustedProxies, remoteAddr: "172.18.0.2:4000", forwarded: "198.51.100.9", wantIP: "198.51.100.9", wantHeaders: true},
		{name: "proxy chain", trusted: config.DefaultTrustedProxies, remoteAddr: "10.0.0.5:4000", forwarded: "8.8.8.8, 198.51.100.9, 10.0.0.4", wantIP: "198.51.100.9", wantHeaders: true},
		{name: "every hop trusted", trusted: config.DefaultTrustedProxies, remoteAddr: "192.168.1.2:4000", forwarded: "192.168.1.50", wantIP: "192.168.1.2", wantHeaders: true},
		{name: "single proxy address", trusted: []string{"192.168.1.2"}, remoteAddr: "192.168.1.2:4000", forwarded: "192.168.1.50", wantIP: "192.168.1.50", wantHeaders: true},
		{name: "trusted IPv6 proxy", trusted: config.DefaultTrustedProxies, remoteAddr: "[fd00::2]:4000", forwarded: "2001:db8::9", wantIP: "2001:db8::9", wantHeaders: true},
		{name: "nothing trusted", trusted: []string{}, remoteAddr: "127.0.0.1:4000", forwarded: "198.51.100.9", wantIP: "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt, err := NewProxyTrust(tt.trusted)
			if err != nil {
				t.Fatalf("NewProxyTrust: %v", err)
			}
			req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
				req.Header.Set("X-Forwarded-Host", "lfs.example.com")
				req.Header.Set("X-Forwarded-Proto", "https")
			}

			var gotIP string
			var gotHeaders bool
			pt.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotIP = ClientIP(r)
				gotHeaders = r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("X-Forwarded-Proto") != ""
			})).ServeHTTP(httptest.NewRecorder(), req)

			if gotIP != tt.wantIP {
				t.Errorf("ClientIP = %q, want %q", gotIP, tt.wantIP)
			}
			if tt.forwarded != "" && gotHeaders != tt.wantHeaders {
				t.Errorf("forwarded headers kept = %t, want %t", gotHeaders, tt.wantHeaders)
			}
		})
	}
}

func TestNewProxyTrustRejectsInvalidEntry(t *testing.T) {
	if _, err := NewProxyTrust([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid trusted proxy")
	}
}

func TestClientIPWithoutProxyTrust(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:4000"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	if ip := ClientIP(req); ip != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want %q", ip, "203.0.113.7")
	}
}

func TestRateLimitIgnoresSpoofedForwardedFor(t *testing.T) {
	store, err := memorystore.New(&memorystore.Config{Tokens: 2, Interval: time.Minute})
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	pt, err := NewProxyTrust(config.DefaultTrustedProxies)
	if err != nil {
		t.Fatalf("NewProxyTrust: %v", err)
	}
	handler := pt.Handler(RateLimit(store, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	var codes []int
	for i := range 4 {
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
		req.RemoteAddr = "203.0.113.7:4000"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("8.8.8.%d", i))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	if want := []int{200, 200, 429, 429}; !slices.Equal(codes, want) {
		t.Fatalf("status codes = %v, want %v", codes, want)
	}
}
