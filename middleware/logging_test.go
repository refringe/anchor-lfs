package middleware

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type accessLogEntry struct {
	Level     string `json:"level"`
	Message   string `json:"message"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Bytes     int64  `json:"bytes"`
	IP        string `json:"ip"`
	RequestID string `json:"request_id"`
}

// captureLog sends the global logger's output to a buffer until the test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = previous })
	return &buf
}

func TestLoggingMiddleware(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		status    int
		wantLevel string
	}{
		{"success", "/org/repo/objects/batch", http.StatusOK, "info"},
		{"client error", "/org/repo/objects/batch", http.StatusNotFound, "warn"},
		{"server error", "/org/repo/objects/batch", http.StatusInternalServerError, "error"},
		{"quiet path success", "/health", http.StatusOK, "debug"},
		{"quiet path failure", "/health", http.StatusServiceUnavailable, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureLog(t)
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("ok"))
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tt.path, nil)
			req.RemoteAddr = "1.2.3.4:1234"
			w := httptest.NewRecorder()
			RequestID(Logging(inner, "/health")).ServeHTTP(w, req)

			if w.Code != tt.status || w.Body.String() != "ok" {
				t.Fatalf("response = %d %q, want %d %q", w.Code, w.Body.String(), tt.status, "ok")
			}
			var got accessLogEntry
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("decoding log line %q: %v", buf.String(), err)
			}
			want := accessLogEntry{
				Level:     tt.wantLevel,
				Message:   "request",
				Method:    http.MethodPost,
				Path:      tt.path,
				Status:    tt.status,
				Bytes:     2,
				IP:        "1.2.3.4",
				RequestID: w.Header().Get(RequestIDHeader),
			}
			if got != want {
				t.Errorf("log entry = %+v, want %+v", got, want)
			}
		})
	}
}
