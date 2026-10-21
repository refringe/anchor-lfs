// Package middleware provides HTTP middleware for proxy-aware client IPs, request IDs, rate limiting and logging.
package middleware

import (
	"encoding/json/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/sethvargo/go-limiter"
)

// maxResetNanos caps the rate limiter reset timestamp to prevent overflow
// when converting to time.Time via time.Unix(0, n).
const maxResetNanos = 1 << 62

// RateLimit returns middleware that enforces per-IP rate limiting using the
// provided limiter store.
func RateLimit(store limiter.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		_, _, reset, ok, err := store.Take(r.Context(), ip)
		if err != nil {
			// Fail open: allow the request through if the rate limiter
			// errors. This prevents a limiter backend failure from causing
			// a total service outage. The tradeoff is that rate limiting is
			// temporarily ineffective during limiter errors.
			Logger(r.Context()).Error().Err(err).Msg("rate limiter error")
			next.ServeHTTP(w, r)
			return
		}
		if !ok {
			retryAfter := max(time.Until(time.Unix(0, min(int64(reset), maxResetNanos))), time.Second)
			w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.MarshalWrite(w, map[string]string{
				"message":           "rate limit exceeded",
				"request_id":        RequestIDFrom(r.Context()),
				"documentation_url": "https://github.com/refringe/anchor-lfs/wiki",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
