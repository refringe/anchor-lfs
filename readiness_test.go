package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/refringe/anchor-lfs/storage"
)

// checkStore is a storage adapter whose Check returns err and counts its calls.
type checkStore struct {
	storage.Adapter
	err   error
	calls int
}

func (s *checkStore) Check(context.Context) error {
	s.calls++
	return s.err
}

func TestReadiness(t *testing.T) {
	tests := []struct {
		name       string
		storeErr   error
		readOnly   bool
		wantStatus int
		wantBody   map[string]string
	}{
		{name: "ready", wantStatus: http.StatusOK, wantBody: map[string]string{"status": "ready"}},
		{
			name:       "storage failing",
			storeErr:   errors.New("bucket unreachable"),
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   map[string]string{"status": "not ready", "failed": "storage"},
		},
		{
			name:       "data directory read-only",
			readOnly:   true,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   map[string]string{"status": "not ready", "failed": "data_directory"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.readOnly {
				if runtime.GOOS == "windows" {
					t.Skip("directory permission bits are not enforced on Windows")
				}
				if os.Geteuid() == 0 {
					t.Skip("root bypasses directory permission checks")
				}
				if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // directories need the execute bit to be traversable
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // directories need the execute bit to be traversable
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ready", nil)
			newReadiness(&checkStore{err: tt.storeErr}, dir).ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding body %q: %v", w.Body.String(), err)
			}
			if !maps.Equal(body, tt.wantBody) {
				t.Errorf("body = %v, want %v", body, tt.wantBody)
			}
		})
	}
}

func TestReadinessReusesRecentResult(t *testing.T) {
	store := &checkStore{}
	rd := newReadiness(store, t.TempDir())

	if failed := rd.check(t.Context()); failed != "" {
		t.Fatalf("first check failed %q", failed)
	}
	store.err = errors.New("bucket unreachable")
	if failed := rd.check(t.Context()); failed != "" || store.calls != 1 {
		t.Fatalf("second check = %q after %d storage checks, want the cached pass after 1", failed, store.calls)
	}

	rd.ttl = 0
	if failed := rd.check(t.Context()); failed != "storage" || store.calls != 2 {
		t.Fatalf("expired check = %q after %d storage checks, want \"storage\" after 2", failed, store.calls)
	}
}

func TestReadyURL(t *testing.T) {
	tests := []struct {
		listen  string
		want    string
		wantErr bool
	}{
		{listen: ":5420", want: "http://127.0.0.1:5420/ready"},
		{listen: "0.0.0.0:8080", want: "http://127.0.0.1:8080/ready"},
		{listen: "[::]:5420", want: "http://[::1]:5420/ready"},
		{listen: "127.0.0.1:5499", want: "http://127.0.0.1:5499/ready"},
		{listen: "lfs.internal:5420", want: "http://lfs.internal:5420/ready"},
		{listen: "5420", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.listen, func(t *testing.T) {
			got, err := readyURL(tt.listen)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readyURL error = %v, want error %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("readyURL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckReady(t *testing.T) {
	notReady := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not ready","failed":"storage"}`))
	}))
	defer notReady.Close()
	if err := checkReady(notReady.URL); err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "storage") {
		t.Errorf("checkReady on a 503 = %v, want an error with the status and body", err)
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if err := checkReady(closed.URL); err == nil {
		t.Error("checkReady on a closed server succeeded")
	}
}

func TestRunHealthcheck(t *testing.T) {
	srv, _ := newIntegrationServer(t, "/org/repo", 1000)
	writeHealthcheckConfig := func(listen string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		content := `
[options]
listen_address = "` + listen + `"

[[endpoints]]
name = "Test"
url = "https://github.com/org/repo"
endpoint = "/org/repo"
visibility = "public"
authentication = "none"
`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	var stdout bytes.Buffer
	if code := runHealthcheck(writeHealthcheckConfig(srv.Listener.Addr().String()), &stdout, io.Discard); code != 0 {
		t.Errorf("runHealthcheck against a ready server = %d, want 0", code)
	}
	if stdout.String() != "ready\n" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "ready\n")
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if code := runHealthcheck(writeHealthcheckConfig(closed.Listener.Addr().String()), io.Discard, io.Discard); code != 1 {
		t.Errorf("runHealthcheck against a stopped server = %d, want 1", code)
	}
}
