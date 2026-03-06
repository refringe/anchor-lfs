package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoggingMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := Logging(inner)

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "ok" {
		t.Fatalf("expected body 'ok', got %q", w.Body.String())
	}
}

func TestLevelForStatus(t *testing.T) {
	tests := []struct {
		status int
	}{
		{200},
		{301},
		{400},
		{404},
		{500},
		{503},
	}

	for _, tt := range tests {
		// Verify logEventForStatus does not panic for various status codes.
		event := logEventForStatus(tt.status)
		if event == nil {
			t.Errorf("logEventForStatus(%d) returned nil", tt.status)
		}
	}
}
