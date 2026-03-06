package lfs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// URLSigner produces and validates HMAC-signed URLs with expiration.
type URLSigner struct {
	key    []byte
	expiry time.Duration
}

// Expiry returns the configured URL expiry duration.
func (s *URLSigner) Expiry() time.Duration {
	return s.expiry
}

// Close zeros the signing key in memory. It should be called during graceful
// shutdown to reduce the window in which key material is recoverable from a
// process memory dump.
func (s *URLSigner) Close() error {
	clear(s.key)
	return nil
}

// NewURLSigner creates a signer. If key is nil or empty, a random 32-byte key
// is generated in memory (callers should prefer persisting the key to disk).
func NewURLSigner(key []byte, expiry time.Duration) (*URLSigner, error) {
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generating signing key: %w", err)
		}
	}
	return &URLSigner{key: key, expiry: expiry}, nil
}

// SignedURL holds a signed URL together with its expiration metadata, all
// derived from a single timestamp to avoid clock skew between fields.
type SignedURL struct {
	Href      string
	ExpiresIn int64
	ExpiresAt string
}

// Sign returns a signed URL with expiration query parameters appended.
// The baseURL is prepended to the signed path for the final href; the MAC
// is computed over the path and expiry only (not the scheme/host).
// The returned SignedURL includes expiration metadata derived from the same
// timestamp used for signing, ensuring consistency across all fields.
func (s *URLSigner) Sign(baseURL, path string) SignedURL {
	now := time.Now()
	expiresAt := now.Add(s.expiry)
	exp := expiresAt.Unix()
	msg := fmt.Sprintf("%s?exp=%d", path, exp)

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return SignedURL{
		Href:      fmt.Sprintf("%s%s?exp=%d&sig=%s", baseURL, path, exp, sig),
		ExpiresIn: int64(s.expiry.Seconds()),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}
}

// Verify checks the signature and expiration of a request URI (path + query).
// Returns nil if valid.
//
// The MAC is computed over "path?exp=<value>" only — the sig parameter and any
// other query parameters are excluded from the signed message. This means
// additional query parameters will not invalidate the signature, but they also
// will not be covered by it. Do not rely on unsigned query parameters for
// security-sensitive decisions.
func (s *URLSigner) Verify(requestURI string) error {
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return errors.New("malformed URL")
	}

	q := u.Query()
	sig := q.Get("sig")
	expStr := q.Get("exp")
	if sig == "" || expStr == "" {
		return errors.New("missing signature parameters")
	}

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return errors.New("invalid expiration")
	}
	if time.Now().Unix() > exp {
		return errors.New("URL has expired")
	}

	// Reconstruct the signed message: path?exp=<value>
	msg := fmt.Sprintf("%s?exp=%s", u.Path, expStr)

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(msg))
	expected := mac.Sum(nil)

	provided, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return errors.New("invalid signature encoding")
	}

	if !hmac.Equal(expected, provided) {
		return errors.New("invalid signature")
	}

	return nil
}
