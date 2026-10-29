package metrics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// scrape returns the metrics m serves.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// assertLines fails the test for each of want that is not a whole line of exposition.
func assertLines(t *testing.T, exposition string, want ...string) {
	t.Helper()
	lines := strings.Split(exposition, "\n")
	for _, line := range want {
		if !slices.Contains(lines, line) {
			t.Errorf("metrics have no line %q", line)
		}
	}
}

func TestInstrument(t *testing.T) {
	m := New("v1.2.3", "abc1234")
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /objects/{oid}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("stored"))
	})
	mux.HandleFunc("/", http.NotFound)
	handler := m.Instrument(mux)

	for _, req := range []*http.Request{
		httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/objects/one", strings.NewReader("12345")),
		httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/objects/two", strings.NewReader("678")),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/unknown/path", nil),
	} {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	assertLines(t, scrape(t, m),
		`anchor_lfs_http_requests_total{code="201",route="PUT /objects/{oid}"} 2`,
		`anchor_lfs_http_requests_total{code="404",route="/"} 1`,
		`anchor_lfs_http_request_duration_seconds_count{route="PUT /objects/{oid}"} 2`,
		`anchor_lfs_http_request_body_bytes_total{route="PUT /objects/{oid}"} 8`,
		`anchor_lfs_http_response_body_bytes_total{route="PUT /objects/{oid}"} 12`,
		`anchor_lfs_build_info{commit="abc1234",version="v1.2.3"} 1`,
	)
}

func TestRegisterAvailableSpace(t *testing.T) {
	tests := []struct {
		name string
		free uint64
		err  error
		want string
	}{
		{name: "free space", free: 1 << 30, want: "anchor_lfs_storage_available_bytes 1.073741824e+09"},
		{name: "error", err: errors.New("statfs failed"), want: "anchor_lfs_storage_available_bytes NaN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New("dev", "unknown")
			m.RegisterAvailableSpace(func(context.Context) (uint64, error) { return tt.free, tt.err })
			assertLines(t, scrape(t, m), tt.want)
		})
	}
}

func TestRegisterAuthCache(t *testing.T) {
	m := New("dev", "unknown")
	m.RegisterAuthCache(func() (hits, misses uint64) { return 7, 2 })
	assertLines(t, scrape(t, m),
		`anchor_lfs_auth_cache_requests_total{result="hit"} 7`,
		`anchor_lfs_auth_cache_requests_total{result="miss"} 2`,
	)
}
