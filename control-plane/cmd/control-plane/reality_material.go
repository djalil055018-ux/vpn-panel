package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func validRealityPublicKey(
	value string,
) bool {
	raw, err :=
		base64.RawURLEncoding.
			DecodeString(value)

	return err == nil &&
		len(raw) == 32
}

func (a *application) agentRealityMaterial(
	w http.ResponseWriter,
	r *http.Request,
) {
	node :=
		currentNode(
			r.Context(),
		)

	var material model.RealityPublicMaterial

	if err :=
		readJSON(
			r,
			&material,
		); err != nil {

		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	material.ServiceID =
		strings.TrimSpace(
			material.ServiceID,
		)

	material.PublicKey =
		strings.TrimSpace(
			material.PublicKey,
		)

	if material.ServiceID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"service_id is required",
		)
		return
	}

	if !validRealityPublicKey(
		material.PublicKey,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid reality public_key",
		)
		return
	}

	err :=
		a.store.SaveRealityPublicMaterial(
			r.Context(),
			node.ID,
			material,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"reality service not found for this node",
		)
		return

	case errors.Is(
		err,
		store.ErrRealityPublicKeyConflict,
	):
		writeError(
			w,
			http.StatusConflict,
			"reality public key does not match previously registered key",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}
