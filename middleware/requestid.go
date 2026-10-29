package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// RequestIDHeader is the header that carries a request's correlation ID in both directions.
const RequestIDHeader = "X-Request-ID"

// validRequestID matches incoming request IDs that are safe to repeat in response headers and log lines.
var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// requestIDKey is the request context key under which RequestID stores the request's ID.
type requestIDKey struct{}

// RequestID gives each request an ID, reusing a valid incoming X-Request-ID, and returns it in the response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !validRequestID.MatchString(id) {
			id = generateRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFrom returns the ID that RequestID assigned to the request, or "" when it has none.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Logger returns the global logger with the request's ID attached when it has one.
func Logger(ctx context.Context) *zerolog.Logger {
	logger := log.Logger
	if id := RequestIDFrom(ctx); id != "" {
		logger = logger.With().Str("request_id", id).Logger()
	}
	return &logger
}

// generateRequestID creates a short random hex string for request correlation.
func generateRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
