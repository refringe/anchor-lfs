// Package sanitise provides path sanitisation functions to prevent directory traversal attacks.
package sanitise

import (
	"path/filepath"
	"regexp"
	"strings"
)

// safeEndpointPattern matches only characters safe for directory names.
var safeEndpointPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// InvalidEndpoint is the fallback directory name for unsafe endpoint paths.
const InvalidEndpoint = "_invalid"

// Endpoint converts an endpoint path into a safe directory name. It strips leading slashes, replaces path separators
// with underscores, and rejects anything containing path traversal or characters outside the safe alphanumeric set.
// Returns InvalidEndpoint for unsafe input.
func Endpoint(endpoint string) string {
	s := strings.TrimLeft(endpoint, "/")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")

	// Rejects traversal sequences (..), absolute paths, and empty strings.
	s, err := filepath.Localize(s) //nolint:misspell // stdlib function name uses American English
	if err != nil {
		return InvalidEndpoint
	}

	if !safeEndpointPattern.MatchString(s) {
		return InvalidEndpoint
	}
	return s
}
