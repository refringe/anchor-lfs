package middleware

import (
	"net/http"
	"slices"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logging logs every request, at debug level for successful requests to quietPaths and by status otherwise.
func Logging(next http.Handler, quietPaths ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(next, w, r)

		event := logEventForStatus(m.Code, slices.Contains(quietPaths, r.URL.Path))
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

func logEventForStatus(status int, quiet bool) *zerolog.Event {
	switch {
	case status >= 500:
		return log.Error()
	case status >= 400:
		return log.Warn()
	case quiet:
		return log.Debug()
	default:
		return log.Info()
	}
}
