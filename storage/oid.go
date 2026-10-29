package storage

import (
	"errors"
	"regexp"
	"strings"
)

// ErrInvalidOID is returned when an object identifier is not a 64-character hexadecimal SHA-256 digest.
var ErrInvalidOID = errors.New("invalid object id")

var oidPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// IsValidOID reports whether oid is a 64-character hexadecimal SHA-256 digest.
func IsValidOID(oid string) bool {
	return oidPattern.MatchString(oid)
}

// normaliseOID returns oid in lowercase, or ErrInvalidOID when it is not a 64-character hexadecimal SHA-256 digest.
func normaliseOID(oid string) (string, error) {
	if !oidPattern.MatchString(oid) {
		return "", ErrInvalidOID
	}
	return strings.ToLower(oid), nil
}
