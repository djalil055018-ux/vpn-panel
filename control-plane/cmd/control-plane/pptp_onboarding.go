package main

import (
	"errors"
	"net/http"
	"vpn-platform/internal/store"
)

func (a *application) registerPPTPOnboardingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/vpn-services/{id}/pptp-clients/{client_id}/rotate-credential", a.requireAdmin(a.rotatePPTPClientCredential))
	mux.HandleFunc("POST /api/v1/core-releases/pptp/import-reviewed", a.requireAdmin(a.importReviewedPPTP))
	mux.HandleFunc("POST /api/v1/core-releases/pptp/approve-reviewed", a.requireAdmin(a.approveReviewedPPTP))
	mux.HandleFunc("POST /api/v1/nodes/{id}/initialize-pptp", a.requireAdmin(a.initializePPTP))
}

func (a *application) rotatePPTPClientCredential(w http.ResponseWriter, r *http.Request) {
	serviceID, clientID := r.PathValue("id"), r.PathValue("client_id")
	if !accessPlanUUID.MatchString(serviceID) || !accessPlanUUID.MatchString(clientID) {
		writeError(w, 400, "invalid service or client id")
		return
	}
	state, err := a.store.RotatePPTPClientCredential(r.Context(), serviceID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "PPTP client binding not found")
		return
	}
	if err != nil {
		writeError(w, 409, "PPTP credential could not be rotated; no changes committed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]any{"generation": state.Generation, "changed": true})
}
func (a *application) importReviewedPPTP(w http.ResponseWriter, r *http.Request) {
	release, created, err := a.store.ImportReviewedPPTP(r.Context())
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
func (a *application) approveReviewedPPTP(w http.ResponseWriter, r *http.Request) {
	if err := a.store.ApproveReviewedPPTP(r.Context()); err != nil {
		writeError(w, 409, "reviewed release is missing, revoked or has different artifact metadata")
		return
	}
	writeJSON(w, 200, map[string]any{"approved": true})
}
func (a *application) initializePPTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !accessPlanUUID.MatchString(id) {
		writeError(w, 400, "invalid node id")
		return
	}
	state, changed, err := a.store.InitializePPTPRuntime(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "node not found")
		return
	}
	if err != nil {
		writeError(w, 409, "initialization requires a compatible registered PPTP node, an approved reviewed release and no enabled services")
		return
	}
	status := http.StatusOK
	if changed {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"node_id": id, "generation": state.Generation, "changed": changed})
}
