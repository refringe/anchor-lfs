package auth

import (
	"context"

	"github.com/refringe/anchor-lfs/config"
)

// Compile-time interface check.
var _ Authenticator = (*None)(nil)

// None is an authenticator that permits all operations without credentials.
type None struct{}

// Authenticate always returns an authenticated and authorized result. The
// username from Basic Auth is preserved for lock ownership; if no username
// is provided, "anonymous" is used.
func (n *None) Authenticate(_ context.Context, _ *config.Endpoint, username, _ string, _ Operation) (Result, error) {
	name := username
	if name == "" {
		name = "anonymous"
	}
	return Result{Authenticated: true, Authorized: true, Username: name}, nil
}
