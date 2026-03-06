// Package lfs implements the Git LFS Batch API protocol, including HTTP handlers, HMAC-signed URL generation, and file
// locking.
package lfs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/refringe/anchor-lfs/auth"
	"github.com/refringe/anchor-lfs/config"
	"github.com/refringe/anchor-lfs/middleware"
	"github.com/refringe/anchor-lfs/storage"
)

// maxRequestBodyBytes caps the size of JSON request bodies (batch, lock, verify) to prevent abuse.
const maxRequestBodyBytes = 1 << 20 // 1 MB

// maxObjectsPerBatch caps the number of objects in a single batch request. Each object triggers storage lookups and
// HMAC signatures, so an explicit bound prevents abuse that the body size limit alone would not catch.
const maxObjectsPerBatch = 1000

type requestIDKeyType struct{}

var requestIDKey = requestIDKeyType{}

// withRequestID stores a request ID in the context.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// getRequestID retrieves the request ID from the context.
func getRequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

const lfsMediaType = "application/vnd.git-lfs+json"

// LFS operation names used in batch requests.
const (
	opDownload = "download"
	opUpload   = "upload"
)

// Handler serves Git LFS API requests for a single endpoint.
type Handler struct {
	endpoint      *config.Endpoint
	store         storage.Adapter
	auth          auth.Authenticator
	baseURL       string
	maxUploadSize int64
	signer        *URLSigner
	lockStore     LockStore
}

// HandlerConfig holds the dependencies for creating a Handler.
type HandlerConfig struct {
	Endpoint      *config.Endpoint
	Store         storage.Adapter
	Auth          auth.Authenticator
	BaseURL       string
	MaxUploadSize int64
	Signer        *URLSigner
	LockStore     LockStore
}

// NewHandler creates a Handler for the given configuration.
func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{
		endpoint:      cfg.Endpoint,
		store:         cfg.Store,
		auth:          cfg.Auth,
		baseURL:       cfg.BaseURL,
		maxUploadSize: cfg.MaxUploadSize,
		signer:        cfg.Signer,
		lockStore:     cfg.LockStore,
	}
}

// assignRequestID generates a request ID, stores it in the request context,
// and sets the X-Request-ID response header.
func assignRequestID(w http.ResponseWriter, r *http.Request) *http.Request {
	id := middleware.GenerateRequestID()
	w.Header().Set("X-Request-ID", id)
	return r.WithContext(withRequestID(r.Context(), id))
}

// BatchHandler handles POST /objects/batch requests.
func (h *Handler) BatchHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	// Validate Accept header per spec — clients must send the LFS media type.
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept != lfsMediaType {
		writeError(w, r, http.StatusNotAcceptable, "expected Accept: "+lfsMediaType)
		return
	}

	// ParseMediaType error is intentionally discarded — a malformed
	// Content-Type produces an empty mediaType, which fails the check below.
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != lfsMediaType {
		writeError(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: "+lfsMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeError(w, r, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, r, http.StatusUnprocessableEntity, "invalid request body")
		return
	}

	if len(req.Objects) > maxObjectsPerBatch {
		writeError(w, r, http.StatusUnprocessableEntity, fmt.Sprintf("batch request contains %d objects; maximum is %d", len(req.Objects), maxObjectsPerBatch))
		return
	}

	if req.Operation != opDownload && req.Operation != opUpload {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid operation")
		return
	}

	// Validate transfer adapters — if the client specifies a list, it must
	// include "basic" (the only adapter this server supports).
	if len(req.Transfers) > 0 && !containsTransfer(req.Transfers, "basic") {
		writeError(w, r, http.StatusUnprocessableEntity, "unsupported transfer adapter; only 'basic' is supported")
		return
	}

	// Validate hash algorithm — only sha256 is supported.
	if req.HashAlgo != "" && req.HashAlgo != "sha256" {
		writeError(w, r, http.StatusConflict, "unsupported hash algorithm; only 'sha256' is supported")
		return
	}

	op := auth.OperationDownload
	if req.Operation == opUpload {
		op = auth.OperationUpload
	}

	if !h.requireAuth(w, r, op) {
		return
	}

	// For uploads, check available disk space before processing objects.
	// This rejects the entire batch early with 507 if the filesystem cannot
	// accommodate the requested uploads, rather than failing individual
	// transfers later.
	if req.Operation == opUpload {
		var totalSize uint64
		for _, obj := range req.Objects {
			if obj.Size > 0 {
				totalSize += uint64(obj.Size)
			}
		}
		if totalSize > 0 {
			avail, err := h.store.AvailableSpace(r.Context())
			if err != nil {
				log.Warn().Err(err).Msg("checking available storage space")
				// Fail open — if we can't check, let individual uploads handle it.
			} else if totalSize > avail {
				writeError(w, r, http.StatusInsufficientStorage, "insufficient storage for requested uploads")
				return
			}
		}
	}

	base := h.requestBaseURL(r)
	resp := h.processBatch(r, &req, base)

	writeJSON(w, http.StatusOK, resp)
}

// DownloadHandler handles GET /objects/{oid} requests.
//
// The HMAC-signed URL already proves the batch handler authorized this request,
// so the requireAuth call below is defence-in-depth: it ensures credentials are
// re-validated even if a signed URL leaks or the signing key is compromised.
func (h *Handler) DownloadHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	if !h.requireValidSignature(w, r) {
		return
	}

	oid := r.PathValue("oid")
	if !isValidOID(oid) {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid object id")
		return
	}

	if !h.requireAuth(w, r, auth.OperationDownload) {
		return
	}

	reader, size, err := h.store.Get(r.Context(), h.endpoint.Path, oid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, r, http.StatusNotFound, "object not found")
		} else {
			log.Error().Err(err).Str("oid", oid).Msg("reading object")
			writeError(w, r, http.StatusInternalServerError, "internal error")
		}
		return
	}
	defer func() { _ = reader.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")

	// OID is the SHA-256 hash — a perfect, immutable ETag.
	w.Header().Set("ETag", `"`+oid+`"`)

	// Use http.ServeContent when the reader supports seeking. This enables
	// range requests (Accept-Ranges: bytes) for resumable downloads and
	// conditional requests (If-None-Match) via the ETag header set above.
	if rs, ok := reader.(io.ReadSeeker); ok {
		http.ServeContent(w, r, "", time.Time{}, rs)
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	if _, err := io.Copy(w, reader); err != nil {
		log.Error().Err(err).Str("oid", oid).Msg("writing download response")
	}
}

// UploadHandler handles PUT /objects/{oid} requests.
//
// The HMAC-signed URL already proves the batch handler authorized this request,
// so the requireAuth call below is defence-in-depth: it ensures credentials are
// re-validated even if a signed URL leaks or the signing key is compromised.
func (h *Handler) UploadHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	if !h.requireValidSignature(w, r) {
		return
	}

	oid := r.PathValue("oid")
	if !isValidOID(oid) {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid object id")
		return
	}

	if !h.requireAuth(w, r, auth.OperationUpload) {
		return
	}

	// The basic transfer spec requires application/octet-stream for uploads.
	// An empty Content-Type is tolerated because some Git LFS clients omit it.
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "" && ct != "application/octet-stream" {
		writeError(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: application/octet-stream")
		return
	}

	if r.ContentLength < 0 {
		writeError(w, r, http.StatusBadRequest, "content-length header required")
		return
	}

	if r.ContentLength > h.maxUploadSize {
		writeError(w, r, http.StatusRequestEntityTooLarge, fmt.Sprintf("object exceeds maximum upload size of %d bytes", h.maxUploadSize))
		return
	}

	exists, err := h.store.Exists(r.Context(), h.endpoint.Path, oid)
	if err != nil {
		log.Error().Err(err).Str("oid", oid).Msg("checking object existence")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	if exists {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Enforce the upload size limit at the reader level.
	body := http.MaxBytesReader(w, r.Body, h.maxUploadSize)

	if err := h.store.Put(r.Context(), h.endpoint.Path, oid, body); err != nil {
		if errors.Is(err, storage.ErrHashMismatch) {
			writeError(w, r, http.StatusBadRequest, "SHA-256 hash mismatch")
			return
		}
		if errors.Is(err, storage.ErrInsufficientStorage) {
			writeError(w, r, http.StatusInsufficientStorage, "insufficient storage")
			return
		}
		log.Error().Err(err).Str("oid", oid).Msg("storing object")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}

	log.Info().
		Str("endpoint", h.endpoint.Name).
		Str("oid", oid).
		Int64("size", r.ContentLength).
		Msg("stored object")

	w.WriteHeader(http.StatusOK)
}

// VerifyHandler handles POST /objects/verify requests.
func (h *Handler) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	if !h.requireValidSignature(w, r) {
		return
	}

	// See BatchHandler for rationale on discarding the ParseMediaType error.
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != lfsMediaType {
		writeError(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: "+lfsMediaType)
		return
	}

	// Verify is a post-upload operation, so it requires push (upload) permission.
	if !h.requireAuth(w, r, auth.OperationUpload) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid request body")
		return
	}

	if !isValidOID(req.OID) {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid object id")
		return
	}

	size, err := h.store.Size(r.Context(), h.endpoint.Path, req.OID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, r, http.StatusNotFound, "object not found")
		} else {
			log.Error().Err(err).Str("oid", req.OID).Msg("checking object size")
			writeError(w, r, http.StatusInternalServerError, "internal error")
		}
		return
	}

	if size != req.Size {
		writeError(w, r, http.StatusUnprocessableEntity, fmt.Sprintf("size mismatch: expected %d, got %d", req.Size, size))
		return
	}

	w.WriteHeader(http.StatusOK)
}

// CreateLockHandler handles POST /{endpoint}/locks requests.
func (h *Handler) CreateLockHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	if !requireLFSMediaType(w, r) {
		return
	}

	result, ok := h.requireAuthResult(w, r, auth.OperationUpload)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req CreateLockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid request body")
		return
	}
	if !isValidLockPath(req.Path) {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid lock path")
		return
	}

	lock, err := h.lockStore.Create(r.Context(), h.endpoint.Path, req.Path, result.Username)
	if err != nil {
		if errors.Is(err, ErrLockExists) {
			writeJSON(w, http.StatusConflict, CreateLockResponse{
				Lock:             lock,
				Message:          "already created lock",
				RequestID:        getRequestID(r.Context()),
				DocumentationURL: documentationURL,
			})
			return
		}
		log.Error().Err(err).Str("endpoint", h.endpoint.Name).Msg("creating lock")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, CreateLockResponse{Lock: lock})
}

// ListLocksHandler handles GET /{endpoint}/locks requests.
// Only Accept is validated (not Content-Type) because GET requests have no body.
func (h *Handler) ListLocksHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)

	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept != lfsMediaType {
		writeError(w, r, http.StatusNotAcceptable, "expected Accept: "+lfsMediaType)
		return
	}

	if _, ok := h.requireAuthResult(w, r, auth.OperationDownload); !ok {
		return
	}

	query := r.URL.Query()
	limit := 0
	if v := query.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, r, http.StatusUnprocessableEntity, "invalid limit parameter")
			return
		}
		limit = n
	}

	locks, nextCursor, err := h.lockStore.List(r.Context(), h.endpoint.Path, ListLocksOptions{
		Path:    query.Get("path"),
		ID:      query.Get("id"),
		Cursor:  query.Get("cursor"),
		Refspec: query.Get("refspec"),
		Limit:   limit,
	})
	if err != nil {
		log.Error().Err(err).Str("endpoint", h.endpoint.Name).Msg("listing locks")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}

	if locks == nil {
		locks = make([]Lock, 0)
	}

	writeJSON(w, http.StatusOK, ListLocksResponse{Locks: locks, NextCursor: nextCursor})
}

// VerifyLocksHandler handles POST /{endpoint}/locks/verify requests.
func (h *Handler) VerifyLocksHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	if !requireLFSMediaType(w, r) {
		return
	}

	result, ok := h.requireAuthResult(w, r, auth.OperationUpload)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req VerifyLocksRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid request body")
		return
	}

	locks, nextCursor, err := h.lockStore.List(r.Context(), h.endpoint.Path, ListLocksOptions{
		Cursor: req.Cursor,
		Limit:  req.Limit,
	})
	if err != nil {
		log.Error().Err(err).Str("endpoint", h.endpoint.Name).Msg("verifying locks")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}

	ours := make([]Lock, 0)
	theirs := make([]Lock, 0)
	for _, l := range locks {
		if strings.EqualFold(l.Owner.Name, result.Username) {
			ours = append(ours, l)
		} else {
			theirs = append(theirs, l)
		}
	}

	writeJSON(w, http.StatusOK, VerifyLocksResponse{
		Ours:       ours,
		Theirs:     theirs,
		NextCursor: nextCursor,
	})
}

// UnlockHandler handles POST /{endpoint}/locks/{id}/unlock requests.
func (h *Handler) UnlockHandler(w http.ResponseWriter, r *http.Request) {
	r = assignRequestID(w, r)
	if !requireLFSMediaType(w, r) {
		return
	}

	result, ok := h.requireAuthResult(w, r, auth.OperationUpload)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid request body")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusUnprocessableEntity, "missing lock id")
		return
	}

	lock, err := h.lockStore.Unlock(r.Context(), h.endpoint.Path, id, result.Username, req.Force)
	if err != nil {
		if errors.Is(err, ErrLockNotFound) {
			writeError(w, r, http.StatusNotFound, "lock not found")
			return
		}
		if errors.Is(err, ErrLockNotOwner) {
			writeError(w, r, http.StatusForbidden, "lock is owned by another user")
			return
		}
		log.Error().Err(err).Str("endpoint", h.endpoint.Name).Msg("unlocking")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, UnlockResponse{Lock: lock})
}

// requireValidSignature checks that the request URL has a valid, non-expired
// HMAC signature. Returns false and writes a 403 error if invalid.
func (h *Handler) requireValidSignature(w http.ResponseWriter, r *http.Request) bool {
	if err := h.signer.Verify(r.URL.RequestURI()); err != nil {
		writeError(w, r, http.StatusForbidden, "invalid or expired URL")
		return false
	}
	return true
}

// requireAuth checks authentication and authorization, writing the appropriate
// error response (401 or 403) if the request is not permitted.
func (h *Handler) requireAuth(w http.ResponseWriter, r *http.Request, op auth.Operation) bool {
	_, ok := h.requireAuthResult(w, r, op)
	return ok
}

// requireAuthResult is like requireAuth but also returns the full auth.Result
// so callers can access the authenticated username.
func (h *Handler) requireAuthResult(w http.ResponseWriter, r *http.Request, op auth.Operation) (auth.Result, bool) {
	result, err := h.authenticate(r, op)
	if err != nil {
		log.Error().Err(err).Str("endpoint", h.endpoint.Name).Msg("authentication error")
		writeError(w, r, http.StatusInternalServerError, "internal error")
		return auth.Result{}, false
	}
	if !result.Authenticated {
		w.Header().Set("LFS-Authenticate", `Basic realm="Anchor LFS"`)
		writeError(w, r, http.StatusUnauthorized, "credentials needed")
		return auth.Result{}, false
	}
	if !result.Authorized {
		writeError(w, r, http.StatusForbidden, "insufficient permissions")
		return auth.Result{}, false
	}
	return result, true
}

// requireLFSMediaType validates that both Accept and Content-Type headers
// are set to the LFS media type. Returns false and writes an error if not.
func requireLFSMediaType(w http.ResponseWriter, r *http.Request) bool {
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept != lfsMediaType {
		writeError(w, r, http.StatusNotAcceptable, "expected Accept: "+lfsMediaType)
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != lfsMediaType {
		writeError(w, r, http.StatusUnsupportedMediaType, "expected Content-Type: "+lfsMediaType)
		return false
	}
	return true
}

func (h *Handler) authenticate(r *http.Request, op auth.Operation) (auth.Result, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		username, password = "", ""
	}
	return h.auth.Authenticate(r.Context(), h.endpoint, username, password, op)
}

// isValidLockPath checks that a lock path is a valid relative file path free of traversal sequences. Lock paths are
// Git-relative file paths (e.g. "assets/model.bin"). Rejects absolute paths, empty strings, traversal sequences (..),
// bare current-directory references ("."), and OS-specific reserved names.
func isValidLockPath(path string) bool {
	if path == "." {
		return false
	}
	_, err := filepath.Localize(path) //nolint:misspell // stdlib function name uses American English
	return err == nil
}

// isValidOID checks that an OID is a well-formed SHA-256 hex string (exactly
// 64 hex characters). This prevents path traversal and rejects malformed input
// before it reaches the storage layer.
func isValidOID(oid string) bool {
	if len(oid) != 64 {
		return false
	}
	_, err := hex.DecodeString(oid)
	return err == nil
}

// requestBaseURL returns the external base URL for action hrefs. If a base URL
// is configured, it is returned directly — this is the recommended approach for
// production deployments as it eliminates trust in forwarded headers.
//
// When no base URL is configured, the function falls back to X-Forwarded-Proto
// and X-Forwarded-Host headers for reverse proxy support. These headers should
// only be set by a trusted proxy — do not expose the server directly to the
// internet without a proxy that controls these headers.
func (h *Handler) requestBaseURL(r *http.Request) string {
	if h.baseURL != "" {
		return h.baseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		scheme = proto
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); isValidForwardedHost(fwdHost) {
		host = fwdHost
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// isValidForwardedHost validates X-Forwarded-Host by attempting to parse it as a URL authority. This is
// defence-in-depth; use base_url in production rather than relying on forwarded headers.
func isValidForwardedHost(host string) bool {
	if host == "" {
		return false
	}
	// url.Parse with a scheme produces a structured URL whose Host field is the parsed authority. If the host
	// contains characters that are invalid in a URL authority, parsing will fail or the Host field will be empty.
	u, err := url.Parse("http://" + host)
	if err != nil || u.Host == "" {
		return false
	}
	// Reject values where url.Parse consumed the host as a path (e.g. bare paths without a dot or port).
	hostname := u.Hostname()
	if hostname == "" {
		return false
	}
	// Ensure the parsed host round-trips cleanly. If the original contained characters that url.Parse escaped or
	// reinterpreted, the round-trip will differ.
	if h, p, splitErr := net.SplitHostPort(host); splitErr == nil {
		return h != "" && p != ""
	}
	// No port; the entire value should be a bare hostname or IPv6 bracket literal.
	return u.Host == host
}

// containsTransfer checks if a transfer adapter name is in the list (case-insensitive).
func containsTransfer(transfers []string, name string) bool {
	for _, t := range transfers {
		if strings.EqualFold(t, name) {
			return true
		}
	}
	return false
}

const documentationURL = "https://github.com/refringe/anchor-lfs/wiki"

// writeJSON marshals v to a buffer before writing, ensuring the response is either fully written or not at all. This
// prevents partial JSON from being sent to the client when encoding fails.
func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Error().Err(err).Msg("marshalling JSON response")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", lfsMediaType)
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	resp := ErrorResponse{
		Message:          message,
		RequestID:        getRequestID(r.Context()),
		DocumentationURL: documentationURL,
	}
	writeJSON(w, status, resp)
}
