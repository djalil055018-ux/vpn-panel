package main

import (
	"errors"
	"net/http"
	"strings"

	"vpn-platform/internal/store"
)

func (a *application) provisionVPNClient(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	clientID :=
		strings.TrimSpace(
			r.PathValue("client_id"),
		)

	if serviceID == "" ||
		clientID == "" {

		writeError(
			w,
			http.StatusBadRequest,
			"service id and client id are required",
		)
		return
	}

	state, err :=
		a.store.AttachVPNClientAndRebuild(
			r.Context(),
			serviceID,
			clientID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"active client or enabled reality service not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"service_id": serviceID,

			"client_id": clientID,

			"generation": state.Generation,

			"status": "accepted",
		},
	)
}
