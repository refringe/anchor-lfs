package middleware

import (
	"net/http"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging is HTTP middleware that logs each request with method, path, status
// code, duration, bytes written, and client IP. It uses httpsnoop to correctly
// capture the response status without breaking optional http.ResponseWriter
// interfaces (Flusher, Hijacker, etc.).
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(next, w, r)

		event := logEventForStatus(m.Code)
		event.
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", m.Code).
			Dur("duration", m.Duration).
			Int64("bytes", m.Written).
			Str("ip", ClientIP(r)).
			Msg("request")
	})
}

func logEventForStatus(status int) *zerolog.Event {
	switch {
	case status >= 500:
		return log.Error()
	case status >= 400:
		return log.Warn()
	default:
		return log.Info()
	}
}
