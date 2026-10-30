package main

import (
	"errors"
	"net/http"
	"time"

	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func (a *application) getNode(
	w http.ResponseWriter,
	r *http.Request,
) {
	node, err :=
		a.store.NodeDetail(
			r.Context(),
			r.PathValue("id"),
			time.Now().UTC(),
		)

	if err == store.ErrNotFound {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		node,
	)
}

func (a *application) nodeLifecycle(
	w http.ResponseWriter,
	r *http.Request,
) {
	status, err :=
		a.store.NodeLifecycle(
			r.Context(),
			r.PathValue("id"),
			time.Now().UTC(),
		)

	if err == store.ErrNotFound {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		status,
	)
}

func (a *application) nodeDiagnostics(
	w http.ResponseWriter,
	r *http.Request,
) {
	result, err :=
		a.store.NodeDiagnostics(
			r.Context(),
			r.PathValue("id"),
			time.Now().UTC(),
		)

	if err == store.ErrNotFound {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		result,
	)
}

func (a *application) rotateNodeBootstrapToken(
	w http.ResponseWriter,
	r *http.Request,
) {
	token, err :=
		security.NewToken(32)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	node, err :=
		a.store.RotateNodeBootstrapToken(
			r.Context(),
			r.PathValue("id"),
			security.HashToken(token),
		)

	if errors.Is(err, store.ErrNodeRetired) {
		writeError(w, http.StatusConflict, "node is deleted")
		return
	}
	if errors.Is(
		err,
		store.ErrNodeAlreadyRegistered,
	) {
		writeError(
			w,
			http.StatusConflict,
			"registered node bootstrap cannot be rotated",
		)
		return
	}

	if err == store.ErrNotFound {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"node": node,

			"bootstrap_token": token,

			"bootstrap_token_note": "shown once; store securely",
		},
	)
}
