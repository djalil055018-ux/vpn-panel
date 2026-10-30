package main

import (
	"errors"
	"net/http"

	"vpn-platform/internal/store"
)

func (a *application) registerXrayOnboardingRoutes(
	mux *http.ServeMux,
) {
	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/initialize-xray",
		a.requireAdmin(a.initializeXray),
	)
}

func (a *application) initializeXray(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := r.PathValue("id")

	if !accessPlanUUID.MatchString(id) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid node id",
		)
		return
	}

	state, changed, err :=
		a.store.InitializeXrayRuntime(
			r.Context(),
			id,
		)

	if errors.Is(err, store.ErrNotFound) {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if errors.Is(err, store.ErrXrayProfileHeld) {
		writeError(w, http.StatusConflict, "imported Xray nodes require the adoption workflow; ordinary initialization is unavailable")
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusConflict,
			"initialization requires a compatible registered Xray node, approved reviewed Xray 26.9.9 and no enabled services",
		)
		return
	}

	status := http.StatusOK

	if changed {
		status = http.StatusAccepted
	}

	writeJSON(
		w,
		status,
		map[string]any{
			"node_id":    id,
			"generation": state.Generation,
			"changed":    changed,
			"core_type":  state.Core.Type,
			"version":    state.Core.Version,
		},
	)
}
