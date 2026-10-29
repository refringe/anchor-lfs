package lfs

import (
	"errors"
	"io"
	"net/http"
	"time"
)

// idleTimeoutReader gives each Read of a request body up to timeout to receive data from the client.
type idleTimeoutReader struct {
	body    io.Reader
	rc      *http.ResponseController
	timeout time.Duration
	ended   bool
}

// withIdleTimeout returns body with a per-read idle timeout, or body itself when timeout is zero or unsupported.
func withIdleTimeout(w http.ResponseWriter, body io.Reader, timeout time.Duration) io.Reader {
	if timeout <= 0 {
		return body
	}
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		return body
	}
	return &idleTimeoutReader{body: body, rc: rc, timeout: timeout}
}

// Read waits up to timeout for data, leaving the connection's deadline alone once the body has ended.
func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	if !r.ended {
		_ = r.rc.SetReadDeadline(time.Now().Add(r.timeout))
	}
	n, err := r.body.Read(p)
	if errors.Is(err, io.EOF) {
		r.ended = true
	}
	return n, err
}
