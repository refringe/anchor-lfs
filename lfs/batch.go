package lfs

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"sync"

	"github.com/refringe/anchor-lfs/middleware"
	"github.com/refringe/anchor-lfs/storage"
)

// batchConcurrency is the number of objects in one batch request that are looked up in storage at the same time.
const batchConcurrency = 16

// processBatch builds the response for every object in req, in request order, stopping early if the client goes away.
func (h *Handler) processBatch(r *http.Request, req *BatchRequest, baseURL string) *BatchResponse {
	objects := make([]ObjectResponse, len(req.Objects))
	slots := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	started := 0
	for i, obj := range req.Objects {
		slots <- struct{}{}
		if r.Context().Err() != nil {
			break
		}
		started++
		wg.Go(func() {
			defer func() { <-slots }()
			objects[i] = h.processObject(r, req.Operation, obj, baseURL)
		})
	}
	wg.Wait()

	return &BatchResponse{
		Transfer: "basic",
		Objects:  objects[:started],
		HashAlgo: "sha256",
	}
}

// processObject builds the response for one object of a batch request.
func (h *Handler) processObject(r *http.Request, operation string, obj Object, baseURL string) ObjectResponse {
	if msg := validateObject(obj); msg != "" {
		return ObjectResponse{
			OID:   obj.OID,
			Size:  obj.Size,
			Error: &ObjectError{Code: 422, Message: msg},
		}
	}
	if operation == opDownload {
		return h.processDownload(r, obj, baseURL)
	}
	return h.processUpload(r, obj, baseURL)
}

func (h *Handler) processDownload(r *http.Request, obj Object, baseURL string) ObjectResponse {
	resp := ObjectResponse{OID: obj.OID, Size: obj.Size}

	size, err := h.store.Size(r.Context(), h.endpoint.Path, obj.OID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			resp.Error = &ObjectError{Code: 404, Message: "object not found"}
		} else {
			middleware.Logger(r.Context()).Error().Err(err).Str("oid", obj.OID).Msg("reading object size")
			resp.Error = &ObjectError{Code: 500, Message: msgInternalError}
		}
		return resp
	}
	if size != obj.Size {
		resp.Error = &ObjectError{
			Code:    422,
			Message: fmt.Sprintf("object size mismatch: expected %d, found %d", obj.Size, size),
		}
		return resp
	}

	// When the storage backend provides presigned URLs, return a direct-to-storage download URL. Otherwise, return an
	// HMAC-signed proxy URL that routes the download through this server.
	if p, ok := h.store.(storage.PresignedURLProvider); ok {
		href, err := p.PresignGet(r.Context(), h.endpoint.Path, obj.OID, h.signer.Expiry())
		if err != nil {
			middleware.Logger(r.Context()).Error().Err(err).Str("oid", obj.OID).Msg("presigning download URL")
			resp.Error = &ObjectError{Code: 500, Message: msgInternalError}
			return resp
		}
		resp.Authenticated = new(bool)
		*resp.Authenticated = true
		resp.Actions = map[string]Action{
			opDownload: {Href: href, ExpiresIn: int64(h.signer.Expiry().Seconds())},
		}
		return resp
	}

	path := fmt.Sprintf("%s/objects/%s", h.endpoint.Path, obj.OID)
	signed := h.signer.Sign(opDownload, baseURL, path)
	resp.Authenticated = new(bool)
	*resp.Authenticated = true
	resp.Actions = map[string]Action{
		opDownload: {
			Href:      signed.Href,
			ExpiresIn: signed.ExpiresIn,
			ExpiresAt: signed.ExpiresAt,
		},
	}
	return resp
}

func (h *Handler) processUpload(r *http.Request, obj Object, baseURL string) ObjectResponse {
	resp := ObjectResponse{OID: obj.OID, Size: obj.Size}

	if obj.Size > h.maxUploadSize {
		resp.Error = &ObjectError{
			Code:    422,
			Message: fmt.Sprintf("object exceeds maximum upload size of %d bytes", h.maxUploadSize),
		}
		return resp
	}

	// If the object already exists, omit actions to signal the server has it.
	exists, err := h.store.Exists(r.Context(), h.endpoint.Path, obj.OID)
	if err != nil {
		middleware.Logger(r.Context()).Error().Err(err).Str("oid", obj.OID).Msg("checking object existence")
		resp.Error = &ObjectError{Code: 500, Message: msgInternalError}
		return resp
	}
	if exists {
		return resp
	}

	// When the storage backend provides presigned URLs, return a direct-to-storage upload URL. The verify action always
	// points back at this server because verification is a server-side check against storage.
	if p, ok := h.store.(storage.PresignedURLProvider); ok {
		href, header, err := p.PresignPut(r.Context(), h.endpoint.Path, obj.OID, obj.Size, h.signer.Expiry())
		if errors.Is(err, storage.ErrObjectTooLarge) {
			resp.Error = &ObjectError{Code: 422, Message: "object exceeds the maximum size for a direct upload to storage"}
			return resp
		}
		if err != nil {
			middleware.Logger(r.Context()).Error().Err(err).Str("oid", obj.OID).Msg("presigning upload URL")
			resp.Error = &ObjectError{Code: 500, Message: msgInternalError}
			return resp
		}
		verifyPath := fmt.Sprintf("%s/objects/verify", h.endpoint.Path)
		signedVerify := h.signer.Sign(opVerify, baseURL, verifyPath)
		resp.Authenticated = new(bool)
		*resp.Authenticated = true
		resp.Actions = map[string]Action{
			opUpload: {Href: href, Header: header, ExpiresIn: int64(h.signer.Expiry().Seconds())},
			opVerify: {
				Href:      signedVerify.Href,
				ExpiresIn: signedVerify.ExpiresIn,
				ExpiresAt: signedVerify.ExpiresAt,
			},
		}
		return resp
	}

	uploadPath := fmt.Sprintf("%s/objects/%s", h.endpoint.Path, obj.OID)
	verifyPath := fmt.Sprintf("%s/objects/verify", h.endpoint.Path)
	signedUpload := h.signer.Sign(opUpload, baseURL, uploadPath)
	signedVerify := h.signer.Sign(opVerify, baseURL, verifyPath)
	resp.Authenticated = new(bool)
	*resp.Authenticated = true
	resp.Actions = map[string]Action{
		opUpload: {
			Href:      signedUpload.Href,
			ExpiresIn: signedUpload.ExpiresIn,
			ExpiresAt: signedUpload.ExpiresAt,
		},
		opVerify: {
			Href:      signedVerify.Href,
			ExpiresIn: signedVerify.ExpiresIn,
			ExpiresAt: signedVerify.ExpiresAt,
		},
	}
	return resp
}

// validateObject returns an error message if the object is invalid, or an
// empty string if it passes validation.
func validateObject(obj Object) string {
	if !storage.IsValidOID(obj.OID) {
		return "invalid object id"
	}
	if obj.Size < 0 {
		return "size must be non-negative"
	}
	return ""
}
