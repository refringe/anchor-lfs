// Package middleware provides HTTP middleware for per-IP rate limiting and structured request logging.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/realclientip/realclientip-go"
	"github.com/rs/zerolog/log"
	"github.com/sethvargo/go-limiter"
)

// ipStrategy extracts the real client IP using proxy-aware header parsing.
// RightmostNonPrivate handles the common case where the server sits behind
// reverse proxies with private IPs. Falls back to RemoteAddr for direct
// connections or when headers are absent.
var ipStrategy = realclientip.NewChainStrategy(
	realclientip.Must(realclientip.NewRightmostNonPrivateStrategy("X-Forwarded-For")),
	realclientip.RemoteAddrStrategy{},
)

// maxResetNanos caps the rate limiter reset timestamp to prevent overflow
// when converting to time.Time via time.Unix(0, n).
const maxResetNanos = 1 << 62

// GenerateRequestID creates a short random hex string for request correlation.
func GenerateRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ClientIP extracts the client IP address from the request.
func ClientIP(r *http.Request) string {
	ip := ipStrategy.ClientIP(r.Header, r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
}

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
			log.Error().Err(err).Msg("rate limiter error")
			next.ServeHTTP(w, r)
			return
		}
		if !ok {
			retryAfter := time.Until(time.Unix(0, min(int64(reset), maxResetNanos)))
			if retryAfter < time.Second {
				retryAfter = time.Second
			}
			requestID := GenerateRequestID()
			w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			w.Header().Set("X-Request-ID", requestID)
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message":           "rate limit exceeded",
				"request_id":        requestID,
				"documentation_url": "https://github.com/refringe/anchor-lfs/wiki",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
