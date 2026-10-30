package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func (a *application) registerAmneziaWGRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/amneziawg/versions", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"versions": []string{"1.0", "1.5", "2.0", "3.0", "3.1"}, "runtime_version": model.AmneziaWGNativeVersion, "minimum_agent": "0.2.42"})
	}))
	mux.HandleFunc("POST /api/v1/core-releases/amneziawg/import-reviewed", a.requireAdmin(a.importReviewedAmneziaWG))
	mux.HandleFunc("POST /api/v1/core-releases/amneziawg/approve-reviewed", a.requireAdmin(a.approveReviewedAmneziaWG))
	mux.HandleFunc("POST /api/v1/nodes/{id}/initialize-amneziawg", a.requireAdmin(a.initializeAmneziaWG))
	for _, method := range []string{"GET", "PUT"} {
		mux.HandleFunc(method+" /api/v1/vpn-services/{id}/amneziawg", a.requireAdmin(a.manageVPNServiceAmneziaWG))
	}
}
func (a *application) importReviewedAmneziaWG(w http.ResponseWriter, r *http.Request) {
	release, created, err := a.store.ImportReviewedAmneziaWG(r.Context())
	if err != nil {
		writeError(w, 409, "reviewed AmneziaWG release could not be imported")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"release": release, "created": created})
}
func (a *application) approveReviewedAmneziaWG(w http.ResponseWriter, r *http.Request) {
	if err := a.store.ApproveReviewedAmneziaWG(r.Context()); err != nil {
		writeError(w, 409, "reviewed AmneziaWG artifact is missing, revoked or inconsistent")
		return
	}
	writeJSON(w, 200, map[string]bool{"approved": true})
}
func (a *application) initializeAmneziaWG(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !accessPlanUUID.MatchString(id) {
		writeError(w, 400, "invalid node id")
		return
	}
	state, changed, err := a.store.InitializeAmneziaWGRuntime(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "node not found")
		return
	}
	if err != nil {
		writeError(w, 409, "initialization requires a compatible registered AmneziaWG node, an approved reviewed release and no enabled services")
		return
	}
	status := http.StatusOK
	if changed {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"node_id": id, "generation": state.Generation, "changed": changed})
}
func (a *application) manageVPNServiceAmneziaWG(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !accessPlanUUID.MatchString(id) {
		writeError(w, 400, "invalid service id")
		return
	}
	if r.Method == "GET" {
		value, err := a.store.GetVPNServiceAmneziaWG(r.Context(), id)
		if err != nil {
			amneziaWGServiceError(w, err)
			return
		}
		writeJSON(w, 200, value)
		return
	}
	var input struct {
		Version string `json:"version"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || !model.ValidAmneziaWGVersion(input.Version) {
		writeError(w, 400, "supported AmneziaWG version is required")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		writeError(w, 400, "body must contain one JSON object")
		return
	}
	value, generation, err := a.store.ConfigureVPNServiceAmneziaWG(r.Context(), id, input.Version)
	if err != nil {
		amneziaWGServiceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"amneziawg": value, "generation": generation})
}
func amneziaWGServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "AmneziaWG configuration not found")
	case errors.Is(err, store.ErrAmneziaWGConfiguration), errors.Is(err, store.ErrNodeRetired), errors.Is(err, store.ErrNodeRuntime):
		writeError(w, 409, "supported AmneziaWG version and a compatible dedicated node are required")
	default:
		writeError(w, 500, "AmneziaWG configuration could not be applied")
	}
}
