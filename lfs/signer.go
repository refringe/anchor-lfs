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

// signatureVersion labels the format of the signed message.
const signatureVersion = "v1"

// Sign returns a URL for operation on baseURL+path that expires after the configured expiry.
func (s *URLSigner) Sign(operation, baseURL, path string) SignedURL {
	expiresAt := time.Now().Add(s.expiry)
	exp := strconv.FormatInt(expiresAt.Unix(), 10)
	sig := base64.RawURLEncoding.EncodeToString(s.mac(operation, baseURL+path, exp))

	return SignedURL{
		Href:      baseURL + path + "?exp=" + exp + "&sig=" + sig,
		ExpiresIn: int64(s.expiry.Seconds()),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}
}

// Verify checks that requestURI, received at baseURL, is unexpired, signed for operation and has no other parameters.
func (s *URLSigner) Verify(operation, baseURL, requestURI string) error {
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return errors.New("malformed URL")
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("malformed query")
	}
	sig := q.Get("sig")
	expStr := q.Get("exp")
	if sig == "" || expStr == "" {
		return errors.New("missing signature parameters")
	}
	if len(q) != 2 || len(q["sig"]) != 1 || len(q["exp"]) != 1 {
		return errors.New("unexpected query parameters")
	}

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return errors.New("invalid expiration")
	}
	if time.Now().Unix() > exp {
		return errors.New("URL has expired")
	}

	provided, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return errors.New("invalid signature encoding")
	}

	if !hmac.Equal(s.mac(operation, baseURL+u.Path, expStr), provided) {
		return errors.New("invalid signature")
	}

	return nil
}

// mac returns the HMAC-SHA256 of the signature version, operation, target URL and expiry, one per line.
func (s *URLSigner) mac(operation, target, exp string) []byte {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(signatureVersion + "\n" + operation + "\n" + target + "\n" + exp))
	return mac.Sum(nil)
}
