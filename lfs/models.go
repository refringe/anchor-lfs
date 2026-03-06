package lfs

// BatchRequest is the incoming request to POST /objects/batch.
type BatchRequest struct {
	Operation string   `json:"operation"`
	Transfers []string `json:"transfers,omitempty"`
	Ref       *Ref     `json:"ref,omitempty"`
	Objects   []Object `json:"objects"`
	HashAlgo  string   `json:"hash_algo,omitempty"`
}

// BatchResponse is the response from POST /objects/batch.
type BatchResponse struct {
	Transfer string           `json:"transfer,omitempty"`
	Objects  []ObjectResponse `json:"objects"`
	HashAlgo string           `json:"hash_algo,omitempty"`
}

// Ref identifies a Git ref associated with a batch request. The spec allows
// servers to use this for ref-aware authorization (e.g., per-branch permissions).
// Anchor LFS authorises at the repository level via GitHub permissions, so the
// ref is accepted for protocol compliance but not used for access decisions.
type Ref struct {
	Name string `json:"name"`
}

// Object represents a single LFS object in a batch request.
type Object struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// ObjectResponse is the per-object response within a batch response.
//
// Authenticated is a pointer so the field is omitted from JSON when nil (object errors) but serialised as true/false
// when set (successful actions). The LFS spec uses this to tell the client whether the server already authenticated
// the action URLs, avoiding redundant credential prompts.
type ObjectResponse struct {
	OID           string            `json:"oid"`
	Size          int64             `json:"size"`
	Authenticated *bool             `json:"authenticated,omitempty"`
	Actions       map[string]Action `json:"actions,omitempty"`
	Error         *ObjectError      `json:"error,omitempty"`
}

// Action describes an LFS transfer action (download, upload, verify).
type Action struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresIn int64             `json:"expires_in,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

// ObjectError is an error attached to a single object in a batch response.
type ObjectError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// VerifyRequest is the incoming request to POST /objects/verify.
type VerifyRequest struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// ErrorResponse is a top-level error response.
type ErrorResponse struct {
	Message          string `json:"message"`
	RequestID        string `json:"request_id,omitempty"`
	DocumentationURL string `json:"documentation_url,omitempty"`
}

// Lock represents a file lock.
type Lock struct {
	ID       string    `json:"id"`
	Path     string    `json:"path"`
	LockedAt string    `json:"locked_at"`
	Owner    LockOwner `json:"owner"`
}

// LockOwner identifies who holds a lock.
type LockOwner struct {
	Name string `json:"name"`
}

// CreateLockRequest is the incoming request to POST /locks.
type CreateLockRequest struct {
	Path string `json:"path"`
	Ref  *Ref   `json:"ref,omitempty"`
}

// CreateLockResponse is the response from POST /locks.
type CreateLockResponse struct {
	Lock             Lock   `json:"lock"`
	Message          string `json:"message,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
	DocumentationURL string `json:"documentation_url,omitempty"`
}

// ListLocksResponse is the response from GET /locks.
type ListLocksResponse struct {
	Locks      []Lock `json:"locks"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// VerifyLocksRequest is the incoming request to POST /locks/verify.
type VerifyLocksRequest struct {
	Ref    *Ref   `json:"ref,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// VerifyLocksResponse is the response from POST /locks/verify.
type VerifyLocksResponse struct {
	Ours       []Lock `json:"ours"`
	Theirs     []Lock `json:"theirs"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// UnlockRequest is the incoming request to POST /locks/:id/unlock.
type UnlockRequest struct {
	Force bool `json:"force,omitempty"`
	Ref   *Ref `json:"ref,omitempty"`
}

// UnlockResponse is the response from POST /locks/:id/unlock.
type UnlockResponse struct {
	Lock Lock `json:"lock"`
}
