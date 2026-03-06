package lfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/refringe/anchor-lfs/auth"
	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/internal/testutil"
	"github.com/refringe/anchor-lfs/storage"
)

func testHandler(t *testing.T) (*Handler, *storage.Local, *URLSigner) {
	t.Helper()
	dir := t.TempDir()
	store := storage.NewLocal(dir)
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
		GitHubOwner:    "org",
		GitHubRepo:     "repo",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        signer,
		LockStore:     lockStore,
	})
	return h, store, signer
}

// signedURI returns a signed request URI for test requests to transfer endpoints.
func signedURI(signer *URLSigner, path string) string {
	signed := signer.Sign("http://test", path)
	// Strip the scheme+host to get just the request URI.
	return signed.Href[len("http://test"):]
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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

	var resp BatchResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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
	uploadURI := signedURI(signer, "/org/repo/objects/"+oid)
	uploadReq := httptest.NewRequestWithContext(context.Background(), "PUT", uploadURI, bytes.NewReader(data))
	uploadReq.ContentLength = int64(len(data))
	uploadReq.SetPathValue("oid", oid)
	uw := httptest.NewRecorder()
	h.UploadHandler(uw, uploadReq)

	if uw.Code != http.StatusOK {
		t.Fatalf("upload: expected 200, got %d: %s", uw.Code, uw.Body.String())
	}

	// Download.
	downloadURI := signedURI(signer, "/org/repo/objects/"+oid)
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
	uploadURI := signedURI(signer, "/org/repo/objects/"+oid)
	uploadReq := httptest.NewRequestWithContext(context.Background(), "PUT", uploadURI, bytes.NewReader(data))
	uploadReq.ContentLength = int64(len(data))
	uploadReq.SetPathValue("oid", oid)
	uw := httptest.NewRecorder()
	h.UploadHandler(uw, uploadReq)

	// Download and check ETag.
	downloadURI := signedURI(signer, "/org/repo/objects/"+oid)
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

func TestUploadHashMismatch(t *testing.T) {
	h, _, signer := testHandler(t)

	data := []byte("test file content")
	badOID := "0000000000000000000000000000000000000000000000000000000000000000"

	uri := signedURI(signer, "/org/repo/objects/"+badOID)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.SetPathValue("oid", badOID)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestUploadMissingContentLength(t *testing.T) {
	h, _, signer := testHandler(t)

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(signer, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, strings.NewReader("data"))
	req.ContentLength = -1
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestUploadRejectsWrongContentType(t *testing.T) {
	h, _, signer := testHandler(t)

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(signer, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, strings.NewReader("data"))
	req.ContentLength = 4
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", w.Code)
	}
}

func TestUploadTooLarge(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewLocal(dir)
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 10, // 10-byte limit
		Signer:        signer,
		LockStore:     lockStore,
	})

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(signer, "/org/repo/objects/"+oid)
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
	uri := signedURI(signer, "/org/repo/objects/"+oid)
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
	if err := store.Put(context.Background(), h.endpoint.Path, oid, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Verify success.
	body, _ := json.Marshal(VerifyRequest{OID: oid, Size: int64(len(data))})
	uri := signedURI(signer, "/org/repo/objects/verify")
	req := httptest.NewRequestWithContext(context.Background(), "POST", uri, bytes.NewReader(body))
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.VerifyHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify size mismatch.
	body, _ = json.Marshal(VerifyRequest{OID: oid, Size: 999})
	uri = signedURI(signer, "/org/repo/objects/verify")
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
	uri := signedURI(signer, "/org/repo/objects/verify")
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
	uri := signedURI(signer, "/org/repo/objects/verify")
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
	dir := t.TempDir()
	store := storage.NewLocal(dir)
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 1024, // 1 KiB limit
		Signer:        signer,
		LockStore:     lockStore,
	})

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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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
	h, _, _ := testHandler(t)

	body := BatchRequest{
		Operation: "download",
		HashAlgo:  "sha1",
		Objects:   []Object{{OID: "deadbeef00000000000000000000000000000000000000000000000000000000", Size: 100}},
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), "POST", "/org/repo/objects/batch", bytes.NewReader(b))
	req.Header.Set("Accept", lfsMediaType)
	req.Header.Set("Content-Type", lfsMediaType)
	w := httptest.NewRecorder()
	h.BatchHandler(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
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
	if err := json.NewDecoder(w.Body).Decode(&createResp); err != nil {
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
	if err := json.NewDecoder(lw.Body).Decode(&listResp); err != nil {
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
	_ = json.NewDecoder(w.Body).Decode(&createResp)

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
	_ = json.NewDecoder(lw.Body).Decode(&listResp)
	if len(listResp.Locks) != 0 {
		t.Fatalf("expected 0 locks after unlock, got %d", len(listResp.Locks))
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

	// Verify locks — should appear in "ours" since same user.
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
	_ = json.NewDecoder(vw.Body).Decode(&verifyResp)
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
	h.BatchHandler(w, req)

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("expected X-Request-ID header")
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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

func TestUploadRejectsExpiredURL(t *testing.T) {
	dir := t.TempDir()
	store := storage.NewLocal(dir)
	expiredSigner, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), -1*time.Second)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        expiredSigner,
		LockStore:     lockStore,
	})

	oid := "deadbeef00000000000000000000000000000000000000000000000000000000"
	uri := signedURI(expiredSigner, "/org/repo/objects/"+oid)
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

func TestBatchUploadInsufficientStorage(t *testing.T) {
	dir := t.TempDir()
	realStore := storage.NewLocal(dir)
	store := &spaceAwareStore{Adapter: realStore, avail: 100} // Only 100 bytes available.
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        signer,
		LockStore:     lockStore,
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

	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatchUploadSufficientStorage(t *testing.T) {
	dir := t.TempDir()
	realStore := storage.NewLocal(dir)
	store := &spaceAwareStore{Adapter: realStore, avail: 1000}
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        signer,
		LockStore:     lockStore,
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBatchUploadSpaceCheckFailsOpen(t *testing.T) {
	dir := t.TempDir()
	realStore := storage.NewLocal(dir)
	store := &spaceAwareStore{Adapter: realStore, availErr: errors.New("statfs failed")}
	signer, err := NewURLSigner([]byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	lockStore := NewFileLockStore(dir)
	ep := &config.Endpoint{
		Name:           "test",
		URL:            "https://github.com/org/repo",
		Path:           "/org/repo",
		Visibility:     "public",
		Authentication: "none",
	}
	h := NewHandler(HandlerConfig{
		Endpoint:      ep,
		Store:         store,
		Auth:          &auth.None{},
		MaxUploadSize: 5 << 30,
		Signer:        signer,
		LockStore:     lockStore,
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
	if err := store.Put(context.Background(), h.endpoint.Path, existingOID, bytes.NewReader(existingData)); err != nil {
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Objects) != 4 {
		t.Fatalf("expected 4 objects, got %d", len(resp.Objects))
	}

	// First object: success — should have download action.
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
	if err := store.Put(context.Background(), h.endpoint.Path, existingOID, bytes.NewReader(existingData)); err != nil {
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
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
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
			uri := signedURI(signer, "/org/repo/objects/"+oid)
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
	downloadURI := signedURI(signer, "/org/repo/objects/"+oid)
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
	uri := signedURI(signer, "/org/repo/objects/"+oid)
	req := httptest.NewRequestWithContext(context.Background(), "PUT", uri, bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.SetPathValue("oid", oid)
	w := httptest.NewRecorder()
	h.UploadHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first upload: expected 200, got %d", w.Code)
	}

	// Second upload of the same object — should succeed (idempotent).
	uri = signedURI(signer, "/org/repo/objects/"+oid)
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
	uri := signedURI(signer, "/org/repo/objects/"+badOID)
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
	uri := signedURI(signer, "/org/repo/objects/"+badOID)
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
	uri := signedURI(signer, "/org/repo/objects/verify")
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

	uri := signedURI(signer, "/org/repo/objects/verify")
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

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}
}
