// Package auth defines the Authenticator interface and provides implementations for GitHub token validation and
// no-op (permissive) authentication.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/refringe/anchor-lfs/config"
)

// ErrUnavailable is wrapped by errors returned when the identity provider fails or cannot be reached.
var ErrUnavailable = errors.New("authentication service unavailable")

// RateLimitedError is returned when the identity provider is rate limiting the caller's credentials.
type RateLimitedError struct {
	RetryAfter time.Duration
}

// Error describes the rate limit and how long until it lifts.
func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("authentication service rate limit exceeded; retry after %s", e.RetryAfter)
}

// Operation represents an LFS operation type (download or upload).
type Operation string

// Supported LFS operations.
const (
	OperationDownload Operation = "download"
	OperationUpload   Operation = "upload"
)

// Result represents the outcome of an authentication attempt.
type Result struct {
	// Authenticated indicates the user provided valid credentials.
	Authenticated bool
	// Authorized indicates the user has permission for the requested operation.
	Authorized bool
	// Username identifies the authenticated user (used for lock ownership).
	Username string
}

// Authenticator checks credentials for an endpoint, returning an error only when the identity provider cannot answer.
type Authenticator interface {
	Authenticate(ctx context.Context, endpoint *config.Endpoint, username, password string, op Operation) (Result, error)
}
