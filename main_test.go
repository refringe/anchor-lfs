package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sethvargo/go-limiter/memorystore"

	"github.com/refringe/anchor-lfs/auth"
	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/internal/metrics"
	"github.com/refringe/anchor-lfs/internal/testutil"
	"github.com/refringe/anchor-lfs/lfs"
	"github.com/refringe/anchor-lfs/middleware"
	"github.com/refringe/anchor-lfs/storage"
)

func TestLoadOrGenerateSigningKeyCreatesFile(t *testing.T) {
	dir := t.TempDir()

	key1, err := loadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}

	// File should exist on disk.
	path := filepath.Join(dir, signingKeyFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	// Second call should load the same key from disk.
	key2, err := loadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("key changed between calls, want the saved key loaded from disk")
	}
}

func TestLoadOrGenerateSigningKeyRejectsInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, signingKeyFile)

	// Write invalid hex.
	if err := os.WriteFile(path, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateSigningKey(dir); err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestLoadOrGenerateSigningKeyRejectsTooShort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, signingKeyFile)

	// Write valid hex but too short (16 bytes = 32 hex chars).
	if err := os.WriteFile(path, []byte("aabbccdd00112233aabbccdd00112233\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateSigningKey(dir); err == nil {
		t.Fatal("expected error for short key")
	}
}

// newIntegrationServer serves an endpoint at endpointPath, allowing rateLimitTokens requests per minute per IP.
func newIntegrationServer(t *testing.T, endpointPath string, rateLimitTokens uint64) (*httptest.Server, *storage.Local) {
	t.Helper()
	dir := t.TempDir()
	store := storage.NewLocal(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           endpointPath,
		Visibility:     "public",
		Authentication: "none",
		GitHubOwner:    "org",
		GitHubRepo:     "repo",
	}
	signer, err := lfs.NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := lfs.NewFileLockStore(dir)
	handler := lfs.NewHandler(lfs.HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        signer,
		LockStore:     lockStore,
	})

	rateLimitStore, err := memorystore.New(&memorystore.Config{Tokens: rateLimitTokens, Interval: time.Minute})
	if err != nil {
		t.Fatalf("creating rate limiter: %v", err)
	}
	t.Cleanup(func() { _ = rateLimitStore.Close(context.Background()) })

	proxyTrust, err := middleware.NewProxyTrust(config.DefaultTrustedProxies)
	if err != nil {
		t.Fatalf("NewProxyTrust: %v", err)
	}

	mux := http.NewServeMux()
	registerRoutes(mux, ep.Path, handler, rateLimitStore)
	registerServiceRoutes(mux, newReadiness(store, dir))

	srv := httptest.NewServer(serverHandler(mux, proxyTrust, true, metrics.New("test", "test")))
	t.Cleanup(srv.Close)
	return srv, store
}

func TestEnsureWritableDirCreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")

	if err := ensureWritableDir(dir); err != nil {
		t.Fatalf("ensureWritableDir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected an empty directory, found %d entries", len(entries))
	}
}

func TestEnsureWritableDirRejectsReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // directories need the execute bit to be traversable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // directories need the execute bit to be traversable

	if err := ensureWritableDir(dir); err == nil {
		t.Fatal("expected an error for a read-only directory")
	}
}

func TestIntegrationRouting(t *testing.T) {
	srv, _ := newIntegrationServer(t, "/org/repo", 1000)

	ctx := t.Context()
	client := srv.Client()

	data := []byte("integration test data")
	hashBytes := sha256.Sum256(data)
	oid := hex.EncodeToString(hashBytes[:])

	// Batch upload request returns signed upload and verify URLs.
	uploadBatchBody, _ := json.Marshal(lfs.BatchRequest{
		Operation: "upload",
		Objects:   []lfs.Object{{OID: oid, Size: int64(len(data))}},
	})
	uploadBatchReq, err := http.NewRequestWithContext(ctx, "POST", srv.URL+"/org/repo/objects/batch", bytes.NewReader(uploadBatchBody))
	if err != nil {
		t.Fatalf("creating batch request: %v", err)
	}
	uploadBatchReq.Header.Set("Accept", "application/vnd.git-lfs+json")
	uploadBatchReq.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	resp, err := client.Do(uploadBatchReq)
	if err != nil {
		t.Fatalf("batch request: %v", err)
	}
	var batchResp lfs.BatchResponse
	if err := json.UnmarshalRead(resp.Body, &batchResp); err != nil {
		t.Fatalf("decoding batch response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch: expected 200, got %d", resp.StatusCode)
	}

	// Upload using the signed URL from the batch response.
	uploadAction := batchResp.Objects[0].Actions["upload"]
	uploadReq, err := http.NewRequestWithContext(ctx, "PUT", uploadAction.Href, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("creating upload request: %v", err)
	}
	uploadReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	resp, err = client.Do(uploadReq)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d", resp.StatusCode)
	}

	// Verify using the signed URL from the batch response.
	verifyAction := batchResp.Objects[0].Actions["verify"]
	verifyBody, _ := json.Marshal(lfs.VerifyRequest{OID: oid, Size: int64(len(data))})
	verifyReq, err := http.NewRequestWithContext(ctx, "POST", verifyAction.Href, bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("creating verify request: %v", err)
	}
	verifyReq.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	resp, err = client.Do(verifyReq)
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d", resp.StatusCode)
	}

	// Batch download request returns a signed download URL.
	downloadBatchBody, _ := json.Marshal(lfs.BatchRequest{
		Operation: "download",
		Objects:   []lfs.Object{{OID: oid, Size: int64(len(data))}},
	})
	downloadBatchReq, err := http.NewRequestWithContext(ctx, "POST", srv.URL+"/org/repo/objects/batch", bytes.NewReader(downloadBatchBody))
	if err != nil {
		t.Fatalf("creating download batch request: %v", err)
	}
	downloadBatchReq.Header.Set("Accept", "application/vnd.git-lfs+json")
	downloadBatchReq.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	resp, err = client.Do(downloadBatchReq)
	if err != nil {
		t.Fatalf("download batch request: %v", err)
	}
	var dlBatchResp lfs.BatchResponse
	if err := json.UnmarshalRead(resp.Body, &dlBatchResp); err != nil {
		t.Fatalf("decoding download batch response: %v", err)
	}
	_ = resp.Body.Close()

	// Download using the signed URL.
	downloadAction := dlBatchResp.Objects[0].Actions["download"]
	downloadReq, err := http.NewRequestWithContext(ctx, "GET", downloadAction.Href, nil)
	if err != nil {
		t.Fatalf("creating download request: %v", err)
	}
	resp, err = client.Do(downloadReq)
	if err != nil {
		t.Fatalf("download request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download: expected 200, got %d", resp.StatusCode)
	}

	// Test unknown path returns 404.
	unknownReq, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/unknown/path", nil)
	if err != nil {
		t.Fatalf("creating unknown path request: %v", err)
	}
	resp, err = client.Do(unknownReq)
	if err != nil {
		t.Fatalf("unknown path request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path: expected 404, got %d", resp.StatusCode)
	}
}

// doLFSRequest sends a request with Git LFS JSON headers and returns its status, Retry-After header and body.
func doLFSRequest(t *testing.T, srv *httptest.Server, method, url string, body []byte) (status int, retryAfter string, respBody []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("creating %s request: %v", method, err)
	}
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("Retry-After"), respBody
}

func TestIntegrationRateLimitsOnlyControlRoutes(t *testing.T) {
	srv, _ := newIntegrationServer(t, "/org/repo", 2)
	batchURL := srv.URL + "/org/repo/objects/batch"
	data := []byte("rate limit test data")
	objects := []lfs.Object{{OID: testutil.SHA256Hex(data), Size: int64(len(data))}}

	actions := func(operation string) map[string]lfs.Action {
		t.Helper()
		body, _ := json.Marshal(lfs.BatchRequest{Operation: operation, Objects: objects})
		status, _, respBody := doLFSRequest(t, srv, http.MethodPost, batchURL, body)
		if status != http.StatusOK {
			t.Fatalf("%s batch: expected 200, got %d", operation, status)
		}
		var resp lfs.BatchResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			t.Fatalf("decoding batch response: %v", err)
		}
		return resp.Objects[0].Actions
	}

	upload := actions("upload")
	if status, _, _ := doLFSRequest(t, srv, http.MethodPut, upload["upload"].Href, data); status != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d", status)
	}
	download := actions("download")

	verifyBody, _ := json.Marshal(lfs.VerifyRequest{OID: objects[0].OID, Size: objects[0].Size})
	for i := range 5 {
		if status, _, _ := doLFSRequest(t, srv, http.MethodPost, upload["verify"].Href, verifyBody); status != http.StatusOK {
			t.Fatalf("verify %d: expected 200, got %d", i+1, status)
		}
		if status, _, _ := doLFSRequest(t, srv, http.MethodGet, download["download"].Href, nil); status != http.StatusOK {
			t.Fatalf("download %d: expected 200, got %d", i+1, status)
		}
	}

	body, _ := json.Marshal(lfs.BatchRequest{Operation: "download", Objects: objects})
	status, retryAfter, _ := doLFSRequest(t, srv, http.MethodPost, batchURL, body)
	if status != http.StatusTooManyRequests {
		t.Fatalf("third batch: expected 429, got %d", status)
	}
	if seconds, err := strconv.Atoi(retryAfter); err != nil || seconds < 1 || seconds > 60 {
		t.Errorf("Retry-After = %q, want 1 to 60 seconds", retryAfter)
	}
}

func TestIntegrationServiceRoutesAndUnknownPaths(t *testing.T) {
	srv, _ := newIntegrationServer(t, "/org/repo", 1000)
	tests := []struct {
		method          string
		path            string
		wantStatus      int
		wantContentType string
		wantKey         string
	}{
		{http.MethodGet, "/", http.StatusOK, "application/json", "version"},
		{http.MethodGet, "/health", http.StatusOK, "application/json", "status"},
		{http.MethodGet, "/ready", http.StatusOK, "application/json", "status"},
		{http.MethodGet, "/unknown/path", http.StatusNotFound, "application/vnd.git-lfs+json", "message"},
		{http.MethodPost, "/", http.StatusNotFound, "application/vnd.git-lfs+json", "message"},
		{http.MethodPost, "/org/wrong-repo/objects/batch", http.StatusNotFound, "application/vnd.git-lfs+json", "message"},
		{http.MethodPost, "/org/wrong-repo/locks/verify", http.StatusNotFound, "application/vnd.git-lfs+json", "message"},
		{http.MethodPost, "/org/repo.git/info/lfs/objects/batch", http.StatusNotFound, "application/vnd.git-lfs+json", "message"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tt.method, srv.URL+tt.path, strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("creating request: %v", err)
			}
			req.Header.Set("Accept", "application/vnd.git-lfs+json")
			req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if got := resp.Header.Get("Content-Type"); got != tt.wantContentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantContentType)
			}
			var body map[string]any
			if err := json.UnmarshalRead(resp.Body, &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if _, ok := body[tt.wantKey]; !ok {
				t.Errorf("body %v has no %q field", body, tt.wantKey)
			}
		})
	}
}

func TestIntegrationRequestIDs(t *testing.T) {
	srv, _ := newIntegrationServer(t, "/org/repo", 1)
	batchBody, _ := json.Marshal(lfs.BatchRequest{Operation: "download", Objects: []lfs.Object{}})
	tests := []struct {
		name       string
		method     string
		path       string
		body       []byte
		incoming   string
		wantStatus int
	}{
		{name: "error with incoming ID", method: http.MethodGet, path: "/unknown", incoming: "proxy-trace-1", wantStatus: http.StatusNotFound},
		{name: "error with generated ID", method: http.MethodGet, path: "/unknown", wantStatus: http.StatusNotFound},
		{name: "first batch", method: http.MethodPost, path: "/org/repo/objects/batch", body: batchBody, wantStatus: http.StatusOK},
		{name: "rate limited batch", method: http.MethodPost, path: "/org/repo/objects/batch", body: batchBody, wantStatus: http.StatusTooManyRequests},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tt.method, srv.URL+tt.path, bytes.NewReader(tt.body))
			if err != nil {
				t.Fatalf("creating request: %v", err)
			}
			req.Header.Set("Accept", "application/vnd.git-lfs+json")
			req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
			if tt.incoming != "" {
				req.Header.Set(middleware.RequestIDHeader, tt.incoming)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			id := resp.Header.Get(middleware.RequestIDHeader)
			if id == "" || (tt.incoming != "" && id != tt.incoming) {
				t.Errorf("X-Request-ID = %q, want %q or a generated ID", id, tt.incoming)
			}
			if tt.wantStatus < http.StatusBadRequest {
				return
			}
			var body struct {
				RequestID string `json:"request_id"`
			}
			if err := json.UnmarshalRead(resp.Body, &body); err != nil {
				t.Fatalf("decoding body: %v", err)
			}
			if body.RequestID != id {
				t.Errorf("body request_id = %q, want header value %q", body.RequestID, id)
			}
		})
	}
}

func TestIntegrationGitLFSClientPush(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git-lfs client test in short mode")
	}
	for _, bin := range []string{"git", "git-lfs"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH", bin)
		}
	}

	for _, endpointPath := range []string{"/org/repo", "/org/repo.js.git/info/lfs"} {
		t.Run(endpointPath, func(t *testing.T) {
			srv, store := newIntegrationServer(t, endpointPath, 1000)

			home := t.TempDir()
			env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
				return strings.HasPrefix(kv, "GIT_") || strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=")
			})
			env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")

			git := func(dir string, args ...string) {
				t.Helper()
				cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // arguments are fixed strings in this test
				cmd.Dir = dir
				cmd.Env = env
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
				}
			}

			remote := t.TempDir()
			git(remote, "init", "--bare")

			repo := t.TempDir()
			git(repo, "init")
			git(repo, "config", "user.name", "Anchor Test")
			git(repo, "config", "user.email", "test@example.com")
			git(repo, "config", "lfs.url", srv.URL+endpointPath)
			git(repo, "remote", "add", "origin", remote)
			git(repo, "lfs", "install", "--local")
			git(repo, "lfs", "track", "*.txt", "*.png")

			files := map[string][]byte{
				"notes.txt": []byte("plain text tracked by Git LFS\n"),
				"image.png": append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), make([]byte, 64)...),
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(repo, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			git(repo, "add", ".gitattributes", "notes.txt", "image.png")
			git(repo, "commit", "-m", "add LFS files")
			git(repo, "lfs", "push", "--all", "origin")

			for name, data := range files {
				exists, err := store.Exists(t.Context(), endpointPath, testutil.SHA256Hex(data))
				if err != nil {
					t.Fatalf("Exists(%s): %v", name, err)
				}
				if !exists {
					t.Errorf("%s was not stored", name)
				}
			}
		})
	}
}
