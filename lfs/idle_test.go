package lfs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/refringe/anchor-lfs/internal/testutil"
	"github.com/refringe/anchor-lfs/storage"
)

const testIdleTimeout = 300 * time.Millisecond

// idleTimeoutServer starts a server storing uploads in store with testIdleTimeout and returns it and its signer.
func idleTimeoutServer(t *testing.T, store storage.Adapter) (*httptest.Server, *URLSigner) {
	t.Helper()
	h, _, signer := testHandler(t, func(cfg *HandlerConfig) {
		cfg.Store = store
		cfg.UploadIdleTimeout = testIdleTimeout
	})
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /org/repo/objects/{oid}", h.UploadHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, signer
}

// slowReader returns data a chunk at a time, sleeping for delay before each chunk.
type slowReader struct {
	data  []byte
	chunk int
	delay time.Duration
}

func (r *slowReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	time.Sleep(r.delay)
	n := copy(p[:min(len(p), r.chunk)], r.data)
	r.data = r.data[n:]
	return n, nil
}

// pausingStore pauses for twice testIdleTimeout between reads of an upload and again after reading past its end.
type pausingStore struct {
	storage.Adapter
}

func (s *pausingStore) Put(ctx context.Context, _, _ string, reader io.Reader, _ int64) error {
	if _, err := io.ReadFull(reader, make([]byte, 32<<10)); err != nil {
		return err
	}
	time.Sleep(2 * testIdleTimeout)
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return err
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("read past the end returned %d bytes: %w", n, err)
	}
	time.Sleep(2 * testIdleTimeout)
	return ctx.Err()
}

// putPartialBody sends 10 bytes of a 1000-byte upload over a raw connection, closing its write side if closeWrite.
func putPartialBody(t *testing.T, srv *httptest.Server, signer *URLSigner, closeWrite bool) *http.Response {
	t.Helper()
	oid := testutil.SHA256Hex(bytes.Repeat([]byte("x"), 1000))
	href := signer.Sign(opUpload, srv.URL, "/org/repo/objects/"+oid).Href

	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := "PUT " + strings.TrimPrefix(href, srv.URL) + " HTTP/1.1\r\nHost: " + srv.Listener.Addr().String() + "\r\nContent-Length: 1000\r\n\r\n" +
		strings.Repeat("x", 10)
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	if closeWrite {
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("connection is a %T, want *net.TCPConn", conn)
		}
		if err := tcpConn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// assertNoTempFiles fails the test if any upload temp file remains under dir.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(entry.Name(), storage.TempFilePrefix) {
			t.Errorf("temporary file %s left behind", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUploadStalledClientTimesOut(t *testing.T) {
	dir := t.TempDir()
	srv, signer := idleTimeoutServer(t, storage.NewLocal(dir))

	start := time.Now()
	resp := putPartialBody(t, srv, signer, false)
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusRequestTimeout)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("stalled upload took %v to time out, want about %v", elapsed, testIdleTimeout)
	}
	assertNoTempFiles(t, dir)
}

func TestUploadEndingEarlyIsAClientError(t *testing.T) {
	dir := t.TempDir()
	srv, signer := idleTimeoutServer(t, storage.NewLocal(dir))

	resp := putPartialBody(t, srv, signer, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	assertNoTempFiles(t, dir)
}

func TestUploadSlowSteadyClientSucceeds(t *testing.T) {
	srv, signer := idleTimeoutServer(t, storage.NewLocal(t.TempDir()))
	data := bytes.Repeat([]byte("y"), 200)
	oid := testutil.SHA256Hex(data)
	href := signer.Sign(opUpload, srv.URL, "/org/repo/objects/"+oid).Href

	body := &slowReader{data: data, chunk: 10, delay: 30 * time.Millisecond}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, href, body)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(data))
	start := time.Now()
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if elapsed := time.Since(start); elapsed <= testIdleTimeout {
		t.Errorf("upload took %v, want longer than the %v idle timeout", elapsed, testIdleTimeout)
	}
}

func TestUploadServerPausesAreNotIdle(t *testing.T) {
	srv, signer := idleTimeoutServer(t, &pausingStore{Adapter: storage.NewLocal(t.TempDir())})
	data := bytes.Repeat([]byte("z"), 64<<10)
	oid := testutil.SHA256Hex(data)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, signer.Sign(opUpload, srv.URL, "/org/repo/objects/"+oid).Href,
		bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
