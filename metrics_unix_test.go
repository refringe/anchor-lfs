//go:build unix

package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestServeMetrics(t *testing.T) {
	p := startServer(t, "5s")
	get := func(url string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}

	if status, _ := get("http://" + p.addr + "/health"); status != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", status)
	}
	if status, _ := get("http://" + p.addr + "/metrics"); status != http.StatusNotFound {
		t.Errorf("GET /metrics on listen_address status = %d, want 404", status)
	}

	status, body := get("http://" + p.metricsAddr + "/metrics")
	if status != http.StatusOK {
		t.Fatalf("GET /metrics on metrics_address status = %d, want 200", status)
	}
	for _, want := range []string{
		`anchor_lfs_http_requests_total{code="200",route="GET /health"} 1`,
		`anchor_lfs_http_requests_total{code="404",route="/"} 1`,
		`anchor_lfs_build_info{commit="unknown",version="dev"} 1`,
		"anchor_lfs_storage_available_bytes ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics do not contain %q", want)
		}
	}
}
