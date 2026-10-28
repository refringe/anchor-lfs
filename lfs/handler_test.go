package lfs

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/refringe/anchor-lfs/auth"
	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/internal/testutil"
	"github.com/refringe/anchor-lfs/middleware"
	"github.com/refringe/anchor-lfs/storage"
)

// testHandler returns a handler for a public /org/repo endpoint on local storage, with options applied to its config.
func testHandler(t *testing.T, options ...func(*HandlerConfig)) (*Handler, *storage.Local, *URLSigner) {
	t.Helper()
	dir := t.TempDir()
	store := storage.NewLocal(dir)
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	cfg := HandlerConfig{
		Endpoint: &config.Endpoint{
			Name:           "test",
			URL:            "https://github.com/org/repo",
			Path:           "/org/repo",
			Visibility:     "public",
			Authentication: "none",
			GitHubOwner:    "org",
			GitHubRepo:     "repo",
		},
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        signer,
		LockStore:     NewFileLockStore(dir),
	}
	for _, option := range options {
		option(&cfg)
	}
	return NewHandler(cfg), store, cfg.Signer
}

// testBaseURL is the base URL of requests built by httptest.NewRequest from a path.
const testBaseURL = "http://example.com"

// signedURI returns the request URI of a URL signed for operation on path at testBaseURL.
func signedURI(signer *URLSigner, operation, path string) string {
	return strings.TrimPrefix(signer.Sign(operation, testBaseURL, path).Href, testBaseURL)
}

func TestBatchDownloadNotFound(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{
		Operation: "download",
		Objects:   []Object{{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 100}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()

	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}
	if resp.Objects[0].Error == nil {
		t.Fatal("expected error for missing object")
	}
	if resp.Objects[0].Error.Code != 404 {
		t.Errorf("expected error code 404, got %d", resp.Objects[0].Error.Code)
	}
}

func TestBatchUploadNewObject(t *testing.T) {
	h, _, _ := testHandler(t)

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	body := BatchRequest{
		Operation: "upload",
		Objects:   []Object{{OID: oid, Size: 100}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()

	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}
	if resp.Objects[0].Actions == nil {
		t.Fatal("expected upload action")
	}
	if _, ok := resp.Objects[0].Actions["upload"]; !ok {
		t.Fatal("expected upload action key")
	}
}

func TestUploadAndDownload(t *testing.T) {
	h, _, signer := testHandler(t)

	data := []byte("test file content")
	oid := testutil.SHA256Hex(data)

	// Upload.
	uploadURI := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
	uploadReq := httptest.NewRequestWithContext(context.Background(), "PUT", uploadURI, bytes.NewReader(data))
	uploadReq.ContentLength = int64(len(data))
	uploadReq.SetPathValue("oid", oid)
	uw := httptest.NewRecorder()
	h.UploadHandler(uw, uploadReq)

	if uw.Code != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d: %s", uw.Code, uw.Body.String())
	}

	// Download.
	downloadURI := signedURI(signer, opDownload, "/org/repo/objects/"+oid)
	downloadReq := httptest.NewRequestWithContext(context.Background(), "GET", downloadURI, nil)
	downloadReq.SetPathValue("oid", oid)
	dw := httptest.NewRecorder()
	h.DownloadHandler(dw, downloadReq)

	if dw.Code != http.StatusOK {
		t.Fatalf("download: expected 200, got %d: %s", dw.Code, dw.Body.String())
	}

	if !bytes.Equal(dw.Body.Bytes(), data) {
		t.Fatal("downloaded data doesn't match uploaded data")
	}
}

func TestDownloadSetsETag(t *testing.T) {
	h, _, signer := testHandler(t)

	data := []byte("etag test content")
	oid := testutil.SHA256Hex(data)

	// Upload first.
	uploadURI := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
	uploadReq := httptest.NewRequestWithContext(context.Background(), "PUT", uploadURI, bytes.NewReader(data))
	uploadReq.ContentLength = int64(len(data))
	uploadReq.SetPathValue("oid", oid)
	uw := httptest.NewRecorder()
	h.UploadHandler(uw, uploadReq)

	// Download and check ETag.
	downloadURI := signedURI(signer, opDownload, "/org/repo/objects/"+oid)
	downloadReq := httptest.NewRequestWithContext(context.Background(), "GET", downloadURI, nil)
	downloadReq.SetPathValue("oid", oid)
	dw := httptest.NewRecorder()
	h.DownloadHandler(dw, downloadReq)

	if dw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", dw.Code)
	}
	etag := dw.Header().Get("ETag")
	if etag != `"`+oid+`"` {
		t.Errorf("ETag = %q, want %q", etag, `"`+oid+`"`)
	}
}

func TestDownloadRangeConditionalAndHead(t *testing.T) {
	h, store, signer := testHandler(t)
	data := []byte("0123456789")
	oid := testutil.SHA256Hex(data)
	if err := store.Put(context.Background(), h.endpoint.Path, oid, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		header     http.Header
		wantStatus int
		wantBody   string
		wantHeader http.Header
	}{
		{
			name:       "range",
			method:     http.MethodGet,
			header:     http.Header{"Range": {"bytes=2-5"}},
			wantStatus: http.StatusPartialContent,
			wantBody:   "2345",
			wantHeader: http.Header{"Content-Range": {"bytes 2-5/10"}, "Content-Length": {"4"}},
		},
		{
			name:       "matching etag",
			method:     http.MethodGet,
			header:     http.Header{"If-None-Match": {`"` + oid + `"`}},
			wantStatus: http.StatusNotModified,
		},
		{
			name:       "other etag",
			method:     http.MethodGet,
			header:     http.Header{"If-None-Match": {`"other"`}},
			wantStatus: http.StatusOK,
			wantBody:   string(data),
		},
		{
			name:       "head",
			method:     http.MethodHead,
			wantStatus: http.StatusOK,
			wantHeader: http.Header{"Content-Length": {"10"}, "Accept-Ranges": {"bytes"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := signedURI(signer, opDownload, "/org/repo/objects/"+oid)
			req := httptest.NewRequestWithContext(context.Background(), tt.method, uri, nil)
			maps.Copy(req.Header, tt.header)
			req.SetPathValue("oid", oid)
			w := httptest.NewRecorder()
			h.DownloadHandler(w, req)

			if w.Code != tt.wantStatus || w.Body.String() != tt.wantBody {
				t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), tt.wantStatus, tt.wantBody)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want %q", got, "no-store")
			}
			for key, want := range tt.wantHeader {
				if got := w.Header().Get(key); got != want[0] {
					t.Errorf("%s = %q, want %q", key, got, want[0])
				}
			}
		})
	}
}

func TestUploadHashMismatch(t *testing.T) {
	h, _, signer := testHandler(t)

	data := []byte("test file content")
	badOID := "0000000000000000000000000000000000000000000000000000000000000000"

	uri := signedURI(signer, opUpload, "/org/repo/objects/"+badOID)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.SetPathValue("oid", badOID)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// putFuncStore wraps a real storage adapter, replacing Put with put.
type putFuncStore struct {
	storage.Adapter
	put func(body io.Reader) error
}

func (s *putFuncStore) Put(_ context.Context, _, _ string, body io.Reader, _ int64) error {
	return s.put(body)
}

func TestUploadInterruptedIsAClientError(t *testing.T) {
	data := []byte("interrupted upload")
	oid := testutil.SHA256Hex(data)
	tests := []struct {
		name       string
		body       io.Reader
		put        func(cancel context.CancelFunc, body io.Reader) error
		wantStatus int
	}{
		{
			name: "body read fails",
			body: io.MultiReader(bytes.NewReader(data[:5]), iotest.ErrReader(errors.New("connection reset by peer"))),
			put: func(_ context.CancelFunc, body io.Reader) error {
				if _, err := io.Copy(io.Discard, body); err != nil {
					return errors.New("upload failed")
				}
				return nil
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "request cancelled",
			body: bytes.NewReader(data),
			put: func(cancel context.CancelFunc, _ io.Reader) error {
				cancel()
				return fmt.Errorf("completing upload: %w", context.Canceled)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "storage fails",
			body: bytes.NewReader(data),
			put: func(context.CancelFunc, io.Reader) error {
				return errors.New("bucket unavailable")
			},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, store, signer := testHandler(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h.store = &putFuncStore{Adapter: store, put: func(body io.Reader) error { return tt.put(cancel, body) }}

			uri := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
			req := httptest.NewRequestWithContext(ctx, http.MethodPut, uri, tt.body)
			req.ContentLength = int64(len(data))
			req.SetPathValue("oid", oid)
			w := httptest.NewRecorder()
			h.UploadHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestUploadWithoutContentLength(t *testing.T) {
	data := []byte("upload without a length")
	oid := testutil.SHA256Hex(data)
	tests := []struct {
		name          string
		maxUploadSize int64
		want          int
	}{
		{"within the limit", 1 << 20, http.StatusOK},
		{"over the limit", int64(len(data)) - 1, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, store, signer := testHandler(t)
			h.maxUploadSize = tt.maxUploadSize
			uri := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
			req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
			req.ContentLength = -1
			req.SetPathValue("oid", oid)
			w := httptest.NewRecorder()
			h.UploadHandler(w, req)

			if w.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tt.want, w.Body.String())
			}
			exists, err := store.Exists(context.Background(), "/org/repo", oid)
			if err != nil {
				t.Fatal(err)
			}
			if exists != (tt.want == http.StatusOK) {
				t.Errorf("object stored = %t, want %t", exists, tt.want == http.StatusOK)
			}
		})
	}
}

func TestUploadChunkedOverHTTP(t *testing.T) {
	h, store, signer := testHandler(t)
	var contentLength int64
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /org/repo/objects/{oid}", func(w http.ResponseWriter, r *http.Request) {
		contentLength = r.ContentLength
		h.UploadHandler(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	data := bytes.Repeat([]byte("c"), 3<<20)
	oid := testutil.SHA256Hex(data)
	href := signer.Sign(opUpload, srv.URL, "/org/repo/objects/"+oid).Href
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, href, struct{ io.Reader }{bytes.NewReader(data)})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || contentLength != -1 {
		t.Fatalf("status %d with request Content-Length %d, want 200 for a chunked request (-1)", resp.StatusCode, contentLength)
	}
	if size, err := store.Size(context.Background(), "/org/repo", oid); err != nil || size != int64(len(data)) {
		t.Errorf("stored size = %d (%v), want %d", size, err, len(data))
	}
}

func TestUploadAcceptsAnyContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
	}{
		{"png", "image/png"},
		{"text with charset", "text/plain; charset=utf-8"},
		{"zip", "application/zip"},
		{"octet-stream", "application/octet-stream"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, store, signer := testHandler(t)

			data := []byte("content sent as " + tt.name)
			oid := testutil.SHA256Hex(data)
			uri := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
			req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
			req.ContentLength = int64(len(data))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			req.SetPathValue("oid", oid)
			w := httptest.NewRecorder()
			h.UploadHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			exists, err := store.Exists(context.Background(), "/org/repo", oid)
			if err != nil {
				t.Fatalf("Exists: %v", err)
			}
			if !exists {
				t.Fatal("object was not stored")
			}
		})
	}
}

func TestUploadTooLarge(t *testing.T) {
	h, _, signer := testHandler(t, func(cfg *HandlerConfig) { cfg.MaxUploadSize = 10 })

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, strings.NewReader("this is way too large"))
	req.ContentLength = 21
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestDownloadNotFound(t *testing.T) {
	h, _, signer := testHandler(t)

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(signer, opDownload, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "GET", uri, nil)
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.DownloadHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestVerifyHandler(t *testing.T) {
	h, store, signer := testHandler(t)

	data := []byte("verify me")
	oid := testutil.SHA256Hex(data)
	if err := store.Put(context.Background(), h.endpoint.Path, oid, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Verify success.
	body, _ := json.Marshal(VerifyRequest{OID: oid, Size: int64(len(data))})
	uri := signedURI(signer, opVerify, "/org/repo/objects/verify")
	req := httptest.NewRequestWithContext(context.Background(), "POST", uri, bytes.NewReader(body))
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify size mismatch.
	body, _ = json.Marshal(VerifyRequest{OID: oid, Size: 999})
	uri = signedURI(signer, opVerify, "/org/repo/objects/verify")
	req = httptest.NewRequestWithContext(context.Background(), "POST", uri, bytes.NewReader(body))
	req.Header.Set("Content-Type", lfsMediaType)
	w = httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestBatchInvalidOperation(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{Operation: "invalid", Objects: []Object{{OID: "abc", Size: 1}}}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestBatchRejectsWrongContentType(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{Operation: "download", Objects: []Object{{OID: "abc", Size: 1}}}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", w.Code)
	}
}

func TestBatchRejectsWrongAccept(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{Operation: "download", Objects: []Object{{OID: "abc", Size: 1}}}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406, got %d", w.Code)
	}
}

func TestVerifyRejectsInvalidOID(t *testing.T) {
	h, _, signer := testHandler(t)

	body, _ := json.Marshal(VerifyRequest{OID: "../../../etc/passwd", Size: 100})
	uri := signedURI(signer, opVerify, "/org/repo/objects/verify")
	req := httptest.NewRequestWithContext(context.Background(), "POST", uri, bytes.NewReader(body))
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestVerifyRejectsWrongContentType(t *testing.T) {
	h, _, signer := testHandler(t)

	body, _ := json.Marshal(VerifyRequest{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 100})
	uri := signedURI(signer, opVerify, "/org/repo/objects/verify")
	req := httptest.NewRequestWithContext(context.Background(), "POST", uri, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", w.Code)
	}
}

func TestBatchRejectsUnsupportedTransfer(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{
		Operation: "download",
		Transfers: []string{"tus"},
		Objects:   []Object{{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 100}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestBatchAcceptsBasicTransfer(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{
		Operation: "download",
		Transfers: []string{"tus", "basic"},
		Objects:   []Object{{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 100}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBatchTooLargeBody(t *testing.T) {
	h, _, _ := testHandler(t)

	padding := strings.Repeat("x", 1<<20+1)
	large := fmt.Appendf(nil, `{"operation":"download","objects":[{"oid":"%s","size":1}]}`, padding)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(large))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestBatchUploadRejectsOversizedObject(t *testing.T) {
	h, _, _ := testHandler(t, func(cfg *HandlerConfig) { cfg.MaxUploadSize = 1024 })

	body := BatchRequest{
		Operation: "upload",
		Objects:   []Object{{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 2048}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}
	if resp.Objects[0].Error == nil || resp.Objects[0].Error.Code != 422 {
		t.Fatalf("expected per-object 422 error, got %+v", resp.Objects[0].Error)
	}
	if resp.Objects[0].Actions != nil {
		t.Fatal("expected no actions for oversized object")
	}
}

func TestBatchAcceptsZeroSizeObject(t *testing.T) {
	h, _, _ := testHandler(t)

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	body := BatchRequest{
		Operation: "upload",
		Objects:   []Object{{OID: oid, Size: 0}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}
	if resp.Objects[0].Error != nil {
		t.Fatalf("expected no error for zero-size object, got %+v", resp.Objects[0].Error)
	}
	if _, ok := resp.Objects[0].Actions["upload"]; !ok {
		t.Fatal("expected upload action for zero-size object")
	}
}

func TestBatchRejectsNegativeSize(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{
		Operation: "download",
		Objects:   []Object{{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: -1}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(resp.Objects))
	}
	if resp.Objects[0].Error == nil || resp.Objects[0].Error.Code != 422 {
		t.Fatalf("expected per-object 422 error, got %+v", resp.Objects[0].Error)
	}
}

func TestBatchRejectsUnsupportedHashAlgo(t *testing.T) {
	body := BatchRequest{
		Operation: "upload",
		HashAlgo:  "sha1",
		Objects:   []Object{{OID: fmt.Sprintf("%064x", 1), Size: 100}, {OID: fmt.Sprintf("%064x", 2), Size: 200}},
	}
	b, _ := json.Marshal(body)
	send := func(h *Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
		req.Header.Set("Accept", lfsMediaType)
		req.Header.Set("Content-Type", lfsMediaType)
		w := httptest.NewRecorder()
		h.BatchHandler(w, req)
		return w
	}

	h, _, _ := testHandler(t)
	w := send(h)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Objects) != 2 || resp.HashAlgo != "sha256" {
		t.Fatalf("got %d objects with hash_algo %q, want 2 with sha256", len(resp.Objects), resp.HashAlgo)
	}
	for _, obj := range resp.Objects {
		if obj.Error == nil || obj.Error.Code != http.StatusConflict || obj.Actions != nil {
			t.Errorf("object %s: error %+v, actions %v; want a 409 error and no actions", obj.OID, obj.Error, obj.Actions)
		}
	}

	h.auth = noCredentialsAuth{}
	if w := send(h); w.Code != http.StatusUnauthorized {
		t.Errorf("without credentials: expected 401, got %d", w.Code)
	}
}

func TestBatchEmptyObjectsReturnsArray(t *testing.T) {
	h, _, _ := testHandler(t)

	body := BatchRequest{Operation: "download", Objects: []Object{}}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	raw := w.Body.String()
	if strings.Contains(raw, `"objects":null`) {
		t.Fatal("expected empty array for objects, got null")
	}
	if !strings.Contains(raw, `"objects":[]`) {
		t.Fatalf("expected empty array in response, got: %s", raw)
	}
}

func TestCreateLockAndList(t *testing.T) {
	h, _, _ := testHandler(t)

	// Create a lock.
	body, _ := json.Marshal(CreateLockRequest{Path: "path/to/file.dat"})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.CreateLockHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var createResp CreateLockResponse
	if err := json.UnmarshalRead(w.Body, &createResp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if createResp.Lock.Path != "path/to/file.dat" {
		t.Errorf("lock path = %q, want %q", createResp.Lock.Path, "path/to/file.dat")
	}
	if createResp.Lock.ID == "" {
		t.Fatal("expected non-empty lock ID")
	}

	// List locks.
	listReq := httptest.NewRequestWithContext(context.Background(), "GET", "/org/repo/locks", nil)
	listReq.Header.Set("Accept", lfsMediaType)
	lw := httptest.NewRecorder()
	h.ListLocksHandler(lw, listReq)

	if lw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", lw.Code, lw.Body.String())
	}

	var listResp ListLocksResponse
	if err := json.UnmarshalRead(lw.Body, &listResp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(listResp.Locks) != 1 {
		t.Fatalf("expected 1 lock, got %d", len(listResp.Locks))
	}
	if listResp.Locks[0].ID != createResp.Lock.ID {
		t.Errorf("lock ID = %q, want %q", listResp.Locks[0].ID, createResp.Lock.ID)
	}
}

func TestCreateLockConflict(t *testing.T) {
	h, _, _ := testHandler(t)

	body, _ := json.Marshal(CreateLockRequest{Path: "same/path"})

	// First create succeeds.
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.CreateLockHandler(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Second create on same path returns 409.
	req = httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w = httptest.NewRecorder()
	h.CreateLockHandler(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnlockHandler(t *testing.T) {
	h, _, _ := testHandler(t)

	// Create a lock.
	body, _ := json.Marshal(CreateLockRequest{Path: "file.txt"})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.CreateLockHandler(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	var createResp CreateLockResponse
	_ = json.UnmarshalRead(w.Body, &createResp)

	// Unlock it.
	unlockBody, _ := json.Marshal(UnlockRequest{})
	unlockReq := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks/"+createResp.Lock.ID+"/unlock", bytes.NewReader(unlockBody))
	unlockReq.Header.Set("Accept", lfsMediaType)
	unlockReq.Header.Set("Content-Type", lfsMediaType)
	unlockReq.SetPathValue("id", createResp.Lock.ID)
	uw := httptest.NewRecorder()
	h.UnlockHandler(uw, unlockReq)
	if uw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", uw.Code, uw.Body.String())
	}

	// List should be empty.
	listReq := httptest.NewRequestWithContext(context.Background(), "GET", "/org/repo/locks", nil)
	listReq.Header.Set("Accept", lfsMediaType)
	lw := httptest.NewRecorder()
	h.ListLocksHandler(lw, listReq)
	var listResp ListLocksResponse
	_ = json.UnmarshalRead(lw.Body, &listResp)
	if len(listResp.Locks) != 0 {
		t.Fatalf("expected 0 locks after unlock, got %d", len(listResp.Locks))
	}
}

// userAuth is an authenticator that authorises every request as user, as a maintainer when maintainer is set.
type userAuth struct {
	user       string
	maintainer bool
}

func (a *userAuth) Authenticate(_ context.Context, _ *config.Endpoint, _, _ string, _ auth.Operation) (auth.Result, error) {
	return auth.Result{Authenticated: true, Authorized: true, Username: a.user, Maintainer: a.maintainer}, nil
}

func TestUnlockForceRequiresMaintainer(t *testing.T) {
	tests := []struct {
		name       string
		requester  string
		maintainer bool
		wantStatus int
	}{
		{"maintainer forces another user's lock", "bob", true, http.StatusOK},
		{"pusher cannot force another user's lock", "bob", false, http.StatusForbidden},
		{"pusher forces their own lock", "alice", false, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _ := testHandler(t)
			lock, err := h.lockStore.Create(context.Background(), h.endpoint.Path, "file.txt", "alice")
			if err != nil {
				t.Fatal(err)
			}
			h.auth = &userAuth{user: tt.requester, maintainer: tt.maintainer}

			body, _ := json.Marshal(UnlockRequest{Force: true})
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks/"+lock.ID+"/unlock", bytes.NewReader(body))
			req.Header.Set("Accept", lfsMediaType)
			req.Header.Set("Content-Type", lfsMediaType)
			req.SetPathValue("id", lock.ID)
			w := httptest.NewRecorder()
			h.UnlockHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantStatus == http.StatusForbidden && !strings.Contains(w.Body.String(), "maintain or admin") {
				t.Errorf("error does not name the required permission: %s", w.Body.String())
			}
			remaining, _, err := h.lockStore.List(context.Background(), h.endpoint.Path, ListLocksOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if released := len(remaining) == 0; released != (tt.wantStatus == http.StatusOK) {
				t.Errorf("lock released = %t, want %t", released, tt.wantStatus == http.StatusOK)
			}
		})
	}
}

func TestVerifyLocksHandler(t *testing.T) {
	h, _, _ := testHandler(t)

	// Create a lock (owned by "anonymous" via None authenticator).
	body, _ := json.Marshal(CreateLockRequest{Path: "file.txt"})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.CreateLockHandler(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Verifying as the lock's owner lists the lock under "ours".
	verifyBody, _ := json.Marshal(VerifyLocksRequest{})
	verifyReq := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks/verify", bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Accept", lfsMediaType)
	verifyReq.Header.Set("Content-Type", lfsMediaType)
	vw := httptest.NewRecorder()
	h.VerifyLocksHandler(vw, verifyReq)
	if vw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", vw.Code, vw.Body.String())
	}
	var verifyResp VerifyLocksResponse
	_ = json.UnmarshalRead(vw.Body, &verifyResp)
	if len(verifyResp.Ours) != 1 {
		t.Fatalf("expected 1 lock in ours, got %d", len(verifyResp.Ours))
	}
	if len(verifyResp.Theirs) != 0 {
		t.Fatalf("expected 0 locks in theirs, got %d", len(verifyResp.Theirs))
	}
}

func TestErrorResponseIncludesRequestID(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", strings.NewReader("{}"))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	middleware.RequestID(http.HandlerFunc(h.BatchHandler)).ServeHTTP(w, req)

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("expected X-Request-ID header")
	}

	var resp ErrorResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if resp.RequestID != rid {
		t.Errorf("request_id = %q, want %q", resp.RequestID, rid)
	}
}

func TestDownloadRejectsUnsignedURL(t *testing.T) {
	h, _, _ := testHandler(t)

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/org/repo/objects/"+oid, nil)
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.DownloadHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unsigned URL, got %d", w.Code)
	}
}

func TestTransferURLsAreBoundToOperationAndHost(t *testing.T) {
	content := []byte("bound object")
	oid := testutil.SHA256Hex(content)
	path := "/org/repo/objects/" + oid

	tests := []struct {
		name          string
		baseURL       string
		signedFor     string
		method        string
		forwardedHost string
		want          int
	}{
		{"download URL downloads", "", opDownload, http.MethodGet, "", http.StatusOK},
		{"download URL cannot upload", "", opDownload, http.MethodPut, "", http.StatusForbidden},
		{"upload URL cannot download", "", opUpload, http.MethodGet, "", http.StatusForbidden},
		{"download URL at another host", "", opDownload, http.MethodGet, "evil.example.com", http.StatusForbidden},
		{"base_url ignores the request host", "https://lfs.example.com", opDownload, http.MethodGet, "evil.example.com", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, store, signer := testHandler(t)
			h.baseURL = tt.baseURL
			if err := store.Put(context.Background(), "/org/repo", oid, bytes.NewReader(content), int64(len(content))); err != nil {
				t.Fatal(err)
			}

			signedBase := cmp.Or(tt.baseURL, testBaseURL)
			uri := strings.TrimPrefix(signer.Sign(tt.signedFor, signedBase, path).Href, signedBase)
			req := httptest.NewRequestWithContext(context.Background(), tt.method, uri, bytes.NewReader(content))
			req.SetPathValue("oid", oid)
			if tt.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
			}
			w := httptest.NewRecorder()
			if tt.method == http.MethodPut {
				h.UploadHandler(w, req)
			} else {
				h.DownloadHandler(w, req)
			}

			if w.Code != tt.want {
				t.Errorf("%s with a URL signed for %s: status %d, want %d", tt.method, tt.signedFor, w.Code, tt.want)
			}
		})
	}
}

func TestUploadRejectsExpiredURL(t *testing.T) {
	expiredSigner, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), -1*time.Second)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	h, _, _ := testHandler(t, func(cfg *HandlerConfig) { cfg.Signer = expiredSigner })

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(expiredSigner, opUpload, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, strings.NewReader("data"))
	req.ContentLength = 4
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired URL, got %d", w.Code)
	}
}

func TestRequestBaseURL(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		host       string
		tls        bool
		fwdProto   string
		fwdHost    string
		wantScheme string
		wantHost   string
	}{
		{
			name:       "plain http",
			host:       "example.com",
			wantScheme: "http",
			wantHost:   "example.com",
		},
		{
			name:       "x-forwarded-proto",
			host:       "example.com",
			fwdProto:   "https",
			wantScheme: "https",
			wantHost:   "example.com",
		},
		{
			name:       "x-forwarded-host",
			host:       "internal:5420",
			fwdHost:    "lfs.example.com",
			wantScheme: "http",
			wantHost:   "lfs.example.com",
		},
		{
			name:       "configured base url overrides headers",
			baseURL:    "https://cdn.example.com",
			host:       "internal:5420",
			fwdProto:   "http",
			fwdHost:    "wrong.example.com",
			wantScheme: "https",
			wantHost:   "cdn.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{baseURL: tt.baseURL}
			req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			req.Host = tt.host
			if tt.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.fwdProto)
			}
			if tt.fwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}

			got := h.requestBaseURL(req)
			want := tt.wantScheme + "://" + tt.wantHost
			if tt.baseURL != "" {
				want = tt.baseURL
			}
			if got != want {
				t.Errorf("requestBaseURL() = %q, want %q", got, want)
			}
		})
	}
}

// spaceAwareStore wraps a real storage adapter, overriding AvailableSpace for testing.
type spaceAwareStore struct {
	storage.Adapter
	avail    uint64
	availErr error
}

func (s *spaceAwareStore) AvailableSpace(_ context.Context) (uint64, error) {
	return s.avail, s.availErr
}

// deniedAuth is an authenticator that accepts every credential but authorises nothing.
type deniedAuth struct{}

func (a *deniedAuth) Authenticate(_ context.Context, _ *config.Endpoint, _, _ string, _ auth.Operation) (auth.Result, error) {
	return auth.Result{Authenticated: true, Username: "carol"}, nil
}

func TestDeniedAccessStatus(t *testing.T) {
	batch := func(operation string) string {
		b, _ := json.Marshal(BatchRequest{Operation: operation, Objects: []Object{{OID: strings.Repeat("a", 64), Size: 1}}})
		return string(b)
	}
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		handler    func(*Handler) http.HandlerFunc
		wantStatus int
		wantMsg    string
	}{
		{"batch download", "POST", "/org/repo/objects/batch", batch("download"), func(h *Handler) http.HandlerFunc { return h.BatchHandler }, http.StatusNotFound, "repository not found"},
		{"batch upload", "POST", "/org/repo/objects/batch", batch("upload"), func(h *Handler) http.HandlerFunc { return h.BatchHandler }, http.StatusForbidden, "insufficient permissions"},
		{"list locks", "GET", "/org/repo/locks", "", func(h *Handler) http.HandlerFunc { return h.ListLocksHandler }, http.StatusForbidden, "insufficient permissions"},
		{"create lock", "POST", "/org/repo/locks", `{"path":"a.bin"}`, func(h *Handler) http.HandlerFunc { return h.CreateLockHandler }, http.StatusForbidden, "insufficient permissions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _ := testHandler(t)
			h.auth = &deniedAuth{}

			req := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Accept", lfsMediaType)
			req.Header.Set("Content-Type", lfsMediaType)
			w := httptest.NewRecorder()
			tt.handler(h)(w, req)

			if w.Code != tt.wantStatus || !strings.Contains(w.Body.String(), tt.wantMsg) {
				t.Fatalf("got %d %s, want %d %q", w.Code, w.Body.String(), tt.wantStatus, tt.wantMsg)
			}
		})
	}
}

// failingAuth is an authenticator that always returns err.
type failingAuth struct {
	err error
}

func (a *failingAuth) Authenticate(_ context.Context, _ *config.Endpoint, _, _ string, _ auth.Operation) (auth.Result, error) {
	return auth.Result{}, a.err
}

func TestBatchAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantRetryAfter string
	}{
		{name: "rate limited", err: &auth.RateLimitedError{RetryAfter: 1500 * time.Millisecond}, wantStatus: http.StatusTooManyRequests, wantRetryAfter: "2"},
		{name: "provider unavailable", err: fmt.Errorf("%w: connection refused", auth.ErrUnavailable), wantStatus: http.StatusBadGateway},
		{name: "unexpected error", err: errors.New("boom"), wantStatus: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _, _ := testHandler(t)
			h.auth = &failingAuth{err: tt.err}

			b, _ := json.Marshal(BatchRequest{Operation: "download", Objects: []Object{{OID: strings.Repeat("a", 64), Size: 1}}})
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
			req.Header.Set("Accept", lfsMediaType)
			req.Header.Set("Content-Type", lfsMediaType)
			w := httptest.NewRecorder()
			h.BatchHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if got := w.Header().Get("Retry-After"); got != tt.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryAfter)
			}
		})
	}
}

// presigningStore wraps a real storage adapter with presigned URLs that refuse objects larger than maxSize.
type presigningStore struct {
	storage.Adapter
	maxSize int64
}

func (s *presigningStore) PresignGet(_ context.Context, _, oid string, _ time.Duration) (string, error) {
	return "https://storage.example/" + oid, nil
}

func (s *presigningStore) PresignPut(_ context.Context, _, oid string, size int64, _ time.Duration) (string, map[string]string, error) {
	if size > s.maxSize {
		return "", nil, storage.ErrObjectTooLarge
	}
	return "https://storage.example/" + oid, map[string]string{"X-Amz-Checksum-Sha256": "checksum-" + oid}, nil
}

func TestBatchUploadPresigned(t *testing.T) {
	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	tests := []struct {
		name       string
		size       int64
		wantHeader map[string]string
		wantError  int
	}{
		{name: "headers forwarded", size: 100, wantHeader: map[string]string{"X-Amz-Checksum-Sha256": "checksum-" + oid}},
		{name: "too large to presign", size: 101, wantError: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, local, _ := testHandler(t)
			h.store = &presigningStore{Adapter: local, maxSize: 100}

			b, _ := json.Marshal(BatchRequest{Operation: "upload", Objects: []Object{{OID: oid, Size: tt.size}}})
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
			req.Header.Set("Accept", lfsMediaType)
			req.Header.Set("Content-Type", lfsMediaType)
			w := httptest.NewRecorder()
			h.BatchHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			var resp BatchResponse
			if err := json.UnmarshalRead(w.Body, &resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			obj := resp.Objects[0]
			if tt.wantError != 0 {
				if obj.Error == nil || obj.Error.Code != tt.wantError {
					t.Fatalf("object error = %+v, want code %d", obj.Error, tt.wantError)
				}
				return
			}
			upload, ok := obj.Actions["upload"]
			if !ok {
				t.Fatalf("expected upload action, got %+v", obj)
			}
			if !maps.Equal(upload.Header, tt.wantHeader) {
				t.Errorf("upload header = %v, want %v", upload.Header, tt.wantHeader)
			}
			if _, ok := obj.Actions["verify"]; !ok {
				t.Error("expected verify action")
			}
		})
	}
}

func TestBatchUploadInsufficientStorage(t *testing.T) {
	h, _, _ := testHandler(t, func(cfg *HandlerConfig) { cfg.Store = &spaceAwareStore{Adapter: cfg.Store, avail: 100} })

	body := BatchRequest{
		Operation: "upload",
		Objects: []Object{
			{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 200},
		},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatchUploadSufficientStorage(t *testing.T) {
	h, _, _ := testHandler(t, func(cfg *HandlerConfig) { cfg.Store = &spaceAwareStore{Adapter: cfg.Store, avail: 1000} })

	body := BatchRequest{
		Operation: "upload",
		Objects: []Object{
			{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 200},
		},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatchUploadSpaceCountsOnlyMissingObjects(t *testing.T) {
	stored := bytes.Repeat([]byte("s"), 1000)
	storedOID := testutil.SHA256Hex(stored)
	missing := func(i int) string { return testutil.SHA256Hex(fmt.Appendf(nil, "missing %d", i)) }

	tests := []struct {
		name    string
		objects []Object
		avail   uint64
		want    int
	}{
		{"stored objects need no space", []Object{{OID: storedOID, Size: 1000}}, 1, http.StatusOK},
		{"stored objects are not counted", []Object{{OID: storedOID, Size: 1000}, {OID: missing(0), Size: 50}}, 100, http.StatusOK},
		{"missing objects need more than is free", []Object{{OID: storedOID, Size: 1000}, {OID: missing(0), Size: 150}}, 100, http.StatusInsufficientStorage},
		{
			"sizes that would wrap the sum",
			[]Object{{OID: missing(0), Size: math.MaxInt64}, {OID: missing(1), Size: math.MaxInt64}, {OID: missing(2), Size: math.MaxInt64}},
			math.MaxUint64 - 1,
			http.StatusInsufficientStorage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, local, _ := testHandler(t)
			if err := local.Put(context.Background(), "/org/repo", storedOID, bytes.NewReader(stored), int64(len(stored))); err != nil {
				t.Fatal(err)
			}
			h.store = &spaceAwareStore{Adapter: local, avail: tt.avail}
			h.maxUploadSize = math.MaxInt64

			b, _ := json.Marshal(BatchRequest{Operation: opUpload, Objects: tt.objects})
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
			req.Header.Set("Accept", lfsMediaType)
			req.Header.Set("Content-Type", lfsMediaType)
			w := httptest.NewRecorder()
			h.BatchHandler(w, req)

			if w.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tt.want, w.Body.String())
			}
		})
	}
}

func TestBatchUploadSpaceCheckFailsOpen(t *testing.T) {
	h, _, _ := testHandler(t, func(cfg *HandlerConfig) {
		cfg.Store = &spaceAwareStore{Adapter: cfg.Store, availErr: errors.New("statfs failed")}
	})

	body := BatchRequest{
		Operation: "upload",
		Objects: []Object{
			{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 200},
		},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	// Should proceed normally (fail open) when space check errors.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail open), got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatchMixedSuccessAndFailure(t *testing.T) {
	h, store, _ := testHandler(t)

	// Upload one object so it exists on disk.
	existingData := []byte("existing object data")
	existingOID := testutil.SHA256Hex(existingData)
	if err := store.Put(context.Background(), h.endpoint.Path, existingOID, bytes.NewReader(existingData), int64(len(existingData))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	missingOID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	invalidOID := "not-a-valid-oid"

	body := BatchRequest{
		Operation: "download",
		Objects: []Object{
			{OID: existingOID, Size: int64(len(existingData))}, // success
			{OID: missingOID, Size: 100},                       // 404
			{OID: invalidOID, Size: 50},                        // 422 invalid OID
			{OID: existingOID, Size: 999},                      // 422 size mismatch
		},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Objects) != 4 {
		t.Fatalf("expected 4 objects, got %d", len(resp.Objects))
	}

	// First object succeeds with a download action.
	if resp.Objects[0].Error != nil {
		t.Errorf("object 0: unexpected error %+v", resp.Objects[0].Error)
	}
	if _, ok := resp.Objects[0].Actions["download"]; !ok {
		t.Error("object 0: expected download action")
	}

	// Second object: not found.
	if resp.Objects[1].Error == nil || resp.Objects[1].Error.Code != 404 {
		t.Errorf("object 1: expected 404 error, got %+v", resp.Objects[1].Error)
	}

	// Third object: invalid OID.
	if resp.Objects[2].Error == nil || resp.Objects[2].Error.Code != 422 {
		t.Errorf("object 2: expected 422 error, got %+v", resp.Objects[2].Error)
	}

	// Fourth object: size mismatch.
	if resp.Objects[3].Error == nil || resp.Objects[3].Error.Code != 422 {
		t.Errorf("object 3: expected 422 error, got %+v", resp.Objects[3].Error)
	}
}

func TestBatchUploadMixedNewAndExisting(t *testing.T) {
	h, store, _ := testHandler(t)

	// Upload one object so it exists.
	existingData := []byte("already here")
	existingOID := testutil.SHA256Hex(existingData)
	if err := store.Put(context.Background(), h.endpoint.Path, existingOID, bytes.NewReader(existingData), int64(len(existingData))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	newOID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	body := BatchRequest{
		Operation: "upload",
		Objects: []Object{
			{OID: existingOID, Size: int64(len(existingData))}, // already exists
			{OID: newOID, Size: 100},                           // needs upload
		},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp BatchResponse
	if err := json.UnmarshalRead(w.Body, &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(resp.Objects))
	}

	// Existing object: no actions (server already has it).
	if resp.Objects[0].Actions != nil {
		t.Errorf("existing object should have no actions, got %v", resp.Objects[0].Actions)
	}
	if resp.Objects[0].Error != nil {
		t.Errorf("existing object should have no error, got %+v", resp.Objects[0].Error)
	}

	// New object: should have upload and verify actions.
	if _, ok := resp.Objects[1].Actions["upload"]; !ok {
		t.Error("new object: expected upload action")
	}
	if _, ok := resp.Objects[1].Actions["verify"]; !ok {
		t.Error("new object: expected verify action")
	}
}

func TestConcurrentUploads(t *testing.T) {
	h, _, signer := testHandler(t)

	data := []byte("concurrent upload data")
	oid := testutil.SHA256Hex(data)

	const goroutines = 10
	errs := make(chan int, goroutines)

	for range goroutines {
		go func() {
			uri := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
			req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
			req.ContentLength = int64(len(data))
			req.SetPathValue("oid", oid)
			w := httptest.NewRecorder()
			h.UploadHandler(w, req)
			errs <- w.Code
		}()
	}

	for range goroutines {
		code := <-errs
		if code != http.StatusOK {
			t.Errorf("concurrent upload returned %d, expected 200", code)
		}
	}

	// Verify the object is readable after concurrent uploads.
	downloadURI := signedURI(signer, opDownload, "/org/repo/objects/"+oid)
	downloadReq := httptest.NewRequestWithContext(context.Background(), "GET", downloadURI, nil)
	downloadReq.SetPathValue("oid", oid)
	dw := httptest.NewRecorder()
	h.DownloadHandler(dw, downloadReq)

	if dw.Code != http.StatusOK {
		t.Fatalf("download after concurrent uploads: expected 200, got %d", dw.Code)
	}
	if !bytes.Equal(dw.Body.Bytes(), data) {
		t.Fatal("downloaded data doesn't match")
	}
}

func TestUploadIdempotent(t *testing.T) {
	h, _, signer := testHandler(t)

	data := []byte("upload me twice")
	oid := testutil.SHA256Hex(data)

	// First upload.
	uri := signedURI(signer, opUpload, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first upload: expected 200, got %d", w.Code)
	}

	// A second upload of the same object succeeds.
	uri = signedURI(signer, opUpload, "/org/repo/objects/"+oid)
	req = httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.SetPathValue("oid", oid)
	w = httptest.NewRecorder()
	h.UploadHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second upload: expected 200, got %d", w.Code)
	}
}

func TestDownloadInvalidOID(t *testing.T) {
	h, _, signer := testHandler(t)

	badOID := "not-valid"
	uri := signedURI(signer, opDownload, "/org/repo/objects/"+badOID)
	req := httptest.NewRequestWithContext(context.Background(), "GET", uri, nil)
	req.SetPathValue("oid", badOID)
	w := httptest.NewRecorder()
	h.DownloadHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestUploadInvalidOID(t *testing.T) {
	h, _, signer := testHandler(t)

	badOID := "zzzz"
	uri := signedURI(signer, opUpload, "/org/repo/objects/"+badOID)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, strings.NewReader("data"))
	req.ContentLength = 4
	req.SetPathValue("oid", badOID)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestVerifyNotFound(t *testing.T) {
	h, _, signer := testHandler(t)

	oid := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	body, _ := json.Marshal(VerifyRequest{OID: oid, Size: 100})
	uri := signedURI(signer, opVerify, "/org/repo/objects/verify")
	req := httptest.NewRequestWithContext(context.Background(), "POST", uri, bytes.NewReader(body))
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestBatchInvalidJSON(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", strings.NewReader("{invalid json"))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestVerifyInvalidJSON(t *testing.T) {
	h, _, signer := testHandler(t)

	uri := signedURI(signer, opVerify, "/org/repo/objects/verify")
	req := httptest.NewRequestWithContext(context.Background(), "POST", uri, strings.NewReader("not json"))
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestCreateLockInvalidPath(t *testing.T) {
	h, _, _ := testHandler(t)

	body, _ := json.Marshal(CreateLockRequest{Path: "../escape"})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.CreateLockHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnlockNotFound(t *testing.T) {
	h, _, _ := testHandler(t)

	body, _ := json.Marshal(UnlockRequest{})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks/nonexistent-id/unlock", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	req.SetPathValue("id", "nonexistent-id")
	w := httptest.NewRecorder()
	h.UnlockHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnlockMissingID(t *testing.T) {
	h, _, _ := testHandler(t)

	body, _ := json.Marshal(UnlockRequest{})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks//unlock", bytes.NewReader(body))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	// Intentionally not setting path value for "id".
	w := httptest.NewRecorder()
	h.UnlockHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestListLocksRejectsWrongAccept(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/org/repo/locks", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ListLocksHandler(w, req)

	if w.Code != http.StatusNotAcceptable {
		t.Fatalf("expected 406, got %d", w.Code)
	}
}

func TestListLocksInvalidLimit(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/org/repo/locks?limit=abc", nil)
	req.Header.Set("Accept", lfsMediaType)
	w := httptest.NewRecorder()
	h.ListLocksHandler(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}

func TestIsValidLockPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"assets/model.bin", true},
		{"file.txt", true},
		{"a/b/c/d.obj", true},
		{"", false},
		{".", false},
		{"/absolute/path", false},
		{"../traversal", false},
		{"a/../b", false},
		{"path\x00evil", false},
		{`a\b`, true},
		{`C:\x`, true},
		{"CON", true},
		{"nul.txt", true},
		{"trailing space ", true},
		{"dir/", false},
		{"a//b", false},
		{"./rel", false},
		{"invalid\xffutf8", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isValidLockPath(tt.path); got != tt.want {
				t.Errorf("isValidLockPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestBatchRejectsTooManyObjects(t *testing.T) {
	h, _, _ := testHandler(t)

	objects := make([]Object, maxObjectsPerBatch+1)
	for i := range objects {
		objects[i] = Object{OID: fmt.Sprintf("%064x", i), Size: 1}
	}
	body := BatchRequest{Operation: "download", Objects: objects}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()

	h.BatchHandler(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestAcceptsLFSMediaType(t *testing.T) {
	tests := []struct {
		accept string
		want   bool
	}{
		{lfsMediaType, true},
		{lfsMediaType + "; charset=utf-8", true},
		{lfsMediaType + ", */*", true},
		{"application/json, " + lfsMediaType, true},
		{"application/*", true},
		{"*/*", true},
		{"", false},
		{"application/json", false},
		{"text/html, " + lfsMediaType + ";q=0", false},
		{lfsMediaType + ";q=0.0, text/html", false},
		{"not a media type", false},
	}
	for _, tt := range tests {
		if got := acceptsLFSMediaType(tt.accept); got != tt.want {
			t.Errorf("acceptsLFSMediaType(%q) = %t, want %t", tt.accept, got, tt.want)
		}
	}
}

func TestBatchAcceptsAcceptList(t *testing.T) {
	h, _, _ := testHandler(t)
	b, _ := json.Marshal(BatchRequest{Operation: opDownload, Objects: []Object{{OID: fmt.Sprintf("%064x", 1), Size: 1}}})
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType+", */*")
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()

	h.BatchHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatchUploadRejectsStoredObjectOfAnotherSize(t *testing.T) {
	h, store, _ := testHandler(t)
	content := []byte("stored content")
	oid := testutil.SHA256Hex(content)
	if err := store.Put(context.Background(), "/org/repo", oid, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}
	objects := []Object{{OID: oid, Size: int64(len(content)) + 1}, {OID: oid, Size: int64(len(content))}}
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", nil)

	resp := h.processBatch(r, &BatchRequest{Operation: opUpload, Objects: objects}, "http://test")

	if got := resp.Objects[0].Error; got == nil || got.Code != http.StatusUnprocessableEntity {
		t.Errorf("wrong declared size: error = %+v, want a 422", got)
	}
	if got := resp.Objects[1]; got.Error != nil || got.Actions != nil {
		t.Errorf("matching declared size: error = %+v, actions = %v, want neither", got.Error, got.Actions)
	}
}

// noCredentialsAuth is an authenticator that treats every request as carrying no valid credentials.
type noCredentialsAuth struct{}

func (noCredentialsAuth) Authenticate(_ context.Context, _ *config.Endpoint, _, _ string, _ auth.Operation) (auth.Result, error) {
	return auth.Result{}, nil
}

func TestLockListingsRejectInvalidCursors(t *testing.T) {
	h, _, _ := testHandler(t)

	listReq := httptest.NewRequestWithContext(context.Background(), "GET", "/org/repo/locks?cursor=not-a-cursor", nil)
	listReq.Header.Set("Accept", lfsMediaType)
	lw := httptest.NewRecorder()
	h.ListLocksHandler(lw, listReq)

	body, _ := json.Marshal(VerifyLocksRequest{Cursor: "not-a-cursor"})
	verifyReq := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks/verify", bytes.NewReader(body))
	verifyReq.Header.Set("Accept", lfsMediaType)
	verifyReq.Header.Set("Content-Type", lfsMediaType)
	vw := httptest.NewRecorder()
	h.VerifyLocksHandler(vw, verifyReq)

	if lw.Code != http.StatusUnprocessableEntity || vw.Code != http.StatusUnprocessableEntity {
		t.Errorf("list status %d, verify status %d; want 422 for both", lw.Code, vw.Code)
	}
}

func TestLockHandlersAuthenticateBeforeCheckingTheRequest(t *testing.T) {
	h, _, _ := testHandler(t)
	h.auth = noCredentialsAuth{}

	handlers := map[string]http.HandlerFunc{
		"create": h.CreateLockHandler,
		"list":   h.ListLocksHandler,
		"verify": h.VerifyLocksHandler,
		"unlock": h.UnlockHandler,
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/locks", strings.NewReader("not json"))
			req.Header.Set("Accept", "text/html")
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", w.Code)
			}
		})
	}
}
