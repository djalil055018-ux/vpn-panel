package main

import (
	"net/http"

	"vpn-platform/internal/store"
)

func (a *application) nodeRuntimeStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	status, err := a.store.NodeRuntimeStatus(
		r.Context(),
		r.PathValue("id"),
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
