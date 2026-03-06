package lfs

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/refringe/anchor-lfs/storage"
)

func (h *Handler) processBatch(r *http.Request, req *BatchRequest, baseURL string) *BatchResponse {
	resp := &BatchResponse{
		Transfer: "basic",
		Objects:  make([]ObjectResponse, 0, len(req.Objects)),
		HashAlgo: "sha256",
	}

	for _, obj := range req.Objects {
		if err := r.Context().Err(); err != nil {
			break
		}

		if msg := validateObject(obj); msg != "" {
			resp.Objects = append(resp.Objects, ObjectResponse{
				OID:  obj.OID,
				Size: obj.Size,
				Error: &ObjectError{
					Code:    422,
					Message: msg,
				},
			})
			continue
		}
		switch req.Operation {
		case opDownload:
			resp.Objects = append(resp.Objects, h.processDownload(r, obj, baseURL))
		case opUpload:
			resp.Objects = append(resp.Objects, h.processUpload(r, obj, baseURL))
		}
	}

	return resp
}

func (h *Handler) processDownload(r *http.Request, obj Object, baseURL string) ObjectResponse {
	resp := ObjectResponse{OID: obj.OID, Size: obj.Size}

	size, err := h.store.Size(r.Context(), h.endpoint.Path, obj.OID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			resp.Error = &ObjectError{Code: 404, Message: "object not found"}
		} else {
			log.Error().Err(err).Str("oid", obj.OID).Msg("reading object size")
			resp.Error = &ObjectError{Code: 500, Message: "internal error"}
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
			log.Error().Err(err).Str("oid", obj.OID).Msg("presigning download URL")
			resp.Error = &ObjectError{Code: 500, Message: "internal error"}
			return resp
		}
		resp.Authenticated = new(bool)
		*resp.Authenticated = true
		resp.Actions = map[string]Action{
			"download": {Href: href, ExpiresIn: int64(h.signer.Expiry().Seconds())},
		}
		return resp
	}

	path := fmt.Sprintf("%s/objects/%s", h.endpoint.Path, obj.OID)
	signed := h.signer.Sign(baseURL, path)
	resp.Authenticated = new(bool)
	*resp.Authenticated = true
	resp.Actions = map[string]Action{
		"download": {
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
		log.Error().Err(err).Str("oid", obj.OID).Msg("checking object existence")
		resp.Error = &ObjectError{Code: 500, Message: "internal error"}
		return resp
	}
	if exists {
		return resp
	}

	// When the storage backend provides presigned URLs, return a direct-to-storage upload URL. The verify action always
	// points back at this server because verification is a server-side check against storage.
	if p, ok := h.store.(storage.PresignedURLProvider); ok {
		href, err := p.PresignPut(r.Context(), h.endpoint.Path, obj.OID, h.signer.Expiry())
		if err != nil {
			log.Error().Err(err).Str("oid", obj.OID).Msg("presigning upload URL")
			resp.Error = &ObjectError{Code: 500, Message: "internal error"}
			return resp
		}
		verifyPath := fmt.Sprintf("%s/objects/verify", h.endpoint.Path)
		signedVerify := h.signer.Sign(baseURL, verifyPath)
		resp.Authenticated = new(bool)
		*resp.Authenticated = true
		resp.Actions = map[string]Action{
			"upload": {Href: href, ExpiresIn: int64(h.signer.Expiry().Seconds())},
			"verify": {
				Href:      signedVerify.Href,
				ExpiresIn: signedVerify.ExpiresIn,
				ExpiresAt: signedVerify.ExpiresAt,
			},
		}
		return resp
	}

	uploadPath := fmt.Sprintf("%s/objects/%s", h.endpoint.Path, obj.OID)
	verifyPath := fmt.Sprintf("%s/objects/verify", h.endpoint.Path)
	signedUpload := h.signer.Sign(baseURL, uploadPath)
	signedVerify := h.signer.Sign(baseURL, verifyPath)
	resp.Authenticated = new(bool)
	*resp.Authenticated = true
	resp.Actions = map[string]Action{
		"upload": {
			Href:      signedUpload.Href,
			ExpiresIn: signedUpload.ExpiresIn,
			ExpiresAt: signedUpload.ExpiresAt,
		},
		"verify": {
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
	if !isValidOID(obj.OID) {
		return "invalid object id"
	}
	if obj.Size < 0 {
		return "size must be non-negative"
	}
	return ""
}
