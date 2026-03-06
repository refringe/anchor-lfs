// Package auth defines the Authenticator interface and provides implementations for GitHub token validation and
// no-op (permissive) authentication.
package auth

import (
	"context"

	"github.com/refringe/anchor-lfs/config"
)

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

// Authenticator validates credentials and checks authorisation for an endpoint.
//
// Implementations must return Result{Authenticated: false} (not an error) when the provided credentials are invalid.
// Errors should only be returned for transient failures such as network errors or upstream service outages. The
// username parameter may be ignored by implementations where the token is self-authenticating (e.g., GitHub PATs).
type Authenticator interface {
	Authenticate(ctx context.Context, endpoint *config.Endpoint, username, password string, op Operation) (Result, error)
}
