package middleware

import (
	"net/http"
	"slices"

	"github.com/felixge/httpsnoop"
	"github.com/rs/zerolog"
)

// Logging logs every request, at debug level for successful requests to quietPaths and by status otherwise.
func Logging(next http.Handler, quietPaths ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(next, w, r)

		event := logEventForStatus(Logger(r.Context()), m.Code, slices.Contains(quietPaths, r.URL.Path))
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

func logEventForStatus(logger *zerolog.Logger, status int, quiet bool) *zerolog.Event {
	switch {
	case status >= 500:
		return logger.Error()
	case status >= 400:
		return logger.Warn()
	case quiet:
		return logger.Debug()
	default:
		return logger.Info()
	}
}
