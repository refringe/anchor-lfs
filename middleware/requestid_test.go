package middleware

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestRequestID(t *testing.T) {
	generated := regexp.MustCompile(`^[0-9a-f]{16}$`)
	tests := []struct {
		name     string
		incoming string
		keep     bool
	}{
		{name: "none sent"},
		{name: "valid", incoming: "trace-01.abc_XYZ", keep: true},
		{name: "maximum length", incoming: strings.Repeat("a", 128), keep: true},
		{name: "too long", incoming: strings.Repeat("a", 129)},
		{name: "unsafe characters", incoming: "id\" injected=\"1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureLog(t)
			var seen string
			inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = RequestIDFrom(r.Context())
				Logger(r.Context()).Info().Msg("handled")
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			if tt.incoming != "" {
				req.Header.Set(RequestIDHeader, tt.incoming)
			}
			w := httptest.NewRecorder()
			RequestID(inner).ServeHTTP(w, req)

			id := w.Header().Get(RequestIDHeader)
			if tt.keep && id != tt.incoming {
				t.Errorf("request ID = %q, want incoming %q", id, tt.incoming)
			}
			if !tt.keep && !generated.MatchString(id) {
				t.Errorf("request ID = %q, want a generated ID", id)
			}
			if seen != id {
				t.Errorf("RequestIDFrom = %q, want %q", seen, id)
			}
			var entry struct {
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("decoding log line %q: %v", buf.String(), err)
			}
			if entry.RequestID != id {
				t.Errorf("logged request_id = %q, want %q", entry.RequestID, id)
			}
		})
	}
}

func TestLoggerWithoutRequestID(t *testing.T) {
	buf := captureLog(t)
	Logger(context.Background()).Info().Msg("no request")
	if strings.Contains(buf.String(), "request_id") {
		t.Errorf("log line %q has a request_id outside a request", buf.String())
	}
}
