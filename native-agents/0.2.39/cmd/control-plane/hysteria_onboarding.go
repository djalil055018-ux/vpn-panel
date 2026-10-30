package main

import (
	"errors"
	"net/http"
	"vpn-platform/internal/store"
)

func (a *application) registerHysteriaOnboardingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/core-releases/hysteria2/import-reviewed", a.requireAdmin(a.importReviewedHysteria))
	mux.HandleFunc("POST /api/v1/core-releases/hysteria2/approve-reviewed", a.requireAdmin(a.approveReviewedHysteria))
	mux.HandleFunc("POST /api/v1/nodes/{id}/initialize-hysteria", a.requireAdmin(a.initializeHysteria))
}
func (a *application) importReviewedHysteria(w http.ResponseWriter, r *http.Request) {
	release, created, err := a.store.ImportReviewedHysteria(r.Context())
	if err != nil {
		writeError(w, 409, "reviewed release could not be imported; check registry integrity")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"release": release, "created": created})
}
func (a *application) approveReviewedHysteria(w http.ResponseWriter, r *http.Request) {
	if err := a.store.ApproveReviewedHysteria(r.Context()); err != nil {
		writeError(w, 409, "reviewed release is missing, revoked or has different artifact metadata")
		return
	}
	writeJSON(w, 200, map[string]any{"approved": true})
}
func (a *application) initializeHysteria(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !accessPlanUUID.MatchString(id) {
		writeError(w, 400, "invalid node id")
		return
	}
	state, changed, err := a.store.InitializeHysteriaRuntime(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "node not found")
		return
	}
	if err != nil {
		writeError(w, 409, "initialization requires a compatible registered Hysteria node, an approved reviewed release and no enabled services")
		return
	}
	status := http.StatusOK
	if changed {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"node_id": id, "generation": state.Generation, "changed": changed})
}
