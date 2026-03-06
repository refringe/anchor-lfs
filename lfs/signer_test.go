package lfs

import (
	"strings"
	"testing"
	"time"
)

func mustNewURLSigner(t *testing.T, key []byte, expiry time.Duration) *URLSigner {
	t.Helper()
	s, err := NewURLSigner(key, expiry)
	if err != nil {
		t.Fatalf("NewURLSigner: %v", err)
	}
	return s
}

func extractRequestURI(t *testing.T, href, path string) string {
	t.Helper()
	idx := strings.Index(href, path)
	if idx < 0 {
		t.Fatalf("signed URL does not contain path %q: %s", path, href)
	}
	return href[idx:]
}

func TestSignAndVerify(t *testing.T) {
	s := mustNewURLSigner(t, []byte("test-secret-key-1234567890abcdef"), 10*time.Minute)

	signed := s.Sign("https://example.com", "/org/repo/objects/abc123")
	if !strings.Contains(signed.Href, "exp=") || !strings.Contains(signed.Href, "sig=") {
		t.Fatalf("signed URL missing parameters: %s", signed.Href)
	}

	requestURI := extractRequestURI(t, signed.Href, "/org/repo")

	if err := s.Verify(requestURI); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	s := mustNewURLSigner(t, []byte("test-secret-key-1234567890abcdef"), 10*time.Minute)

	signed := s.Sign("https://example.com", "/org/repo/objects/abc123")
	requestURI := extractRequestURI(t, signed.Href, "/org/repo")

	// Tamper with the signature.
	tampered := strings.Replace(requestURI, "sig=", "sig=XXXX", 1)
	if err := s.Verify(tampered); err == nil {
		t.Fatal("tampered signature should be rejected")
	}
}

func TestVerifyExpired(t *testing.T) {
	// Use a very short expiry so it expires immediately.
	s := mustNewURLSigner(t, []byte("test-secret-key-1234567890abcdef"), -1*time.Second)

	signed := s.Sign("https://example.com", "/org/repo/objects/abc123")
	requestURI := extractRequestURI(t, signed.Href, "/org/repo")

	if err := s.Verify(requestURI); err == nil {
		t.Fatal("expired URL should be rejected")
	}
}

func TestVerifyMissingParams(t *testing.T) {
	s := mustNewURLSigner(t, []byte("test-secret-key-1234567890abcdef"), 10*time.Minute)

	if err := s.Verify("/org/repo/objects/abc123"); err == nil {
		t.Fatal("URL without sig/exp should be rejected")
	}
}

func TestSignedURLExpiresIn(t *testing.T) {
	s := mustNewURLSigner(t, nil, 10*time.Minute)
	signed := s.Sign("https://example.com", "/test")
	if signed.ExpiresIn != 600 {
		t.Errorf("ExpiresIn = %d, want 600", signed.ExpiresIn)
	}
}

func TestSignedURLExpiresAtConsistency(t *testing.T) {
	s := mustNewURLSigner(t, []byte("test-secret-key-1234567890abcdef"), 10*time.Minute)
	signed := s.Sign("https://example.com", "/test")
	if signed.ExpiresAt == "" {
		t.Fatal("ExpiresAt should not be empty")
	}
	if signed.ExpiresIn != 600 {
		t.Errorf("ExpiresIn = %d, want 600", signed.ExpiresIn)
	}
}

func TestNewURLSignerGeneratesKey(t *testing.T) {
	s := mustNewURLSigner(t, nil, 10*time.Minute)
	if len(s.key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(s.key))
	}
}
