package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func agentFleetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "agent update unavailable")
	case errors.Is(err, store.ErrAdminPermission):
		writeError(w, 403, "owner role required")
	case errors.Is(err, store.ErrAgentFleetConflict):
		writeError(w, 409, "agent update state changed; inspect the current fleet status")
	default:
		writeError(w, 503, "agent update service unavailable")
	}
}
func (a *application) registerAgentFleetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/agent-updates", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		value, err := a.store.AgentFleetStatus(r.Context())
		if err != nil {
			agentFleetError(w, err)
			return
		}
		writeJSON(w, 200, value)
	}))
	mux.HandleFunc("POST /api/v1/agent-releases", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if !adminOwnerRequired(w, r) {
			return
		}
		var input model.AgentRelease
		if tenantReadJSON(w, r, &input) != nil {
			writeError(w, 400, "invalid agent release")
			return
		}
		if err := a.store.RegisterAgentRelease(r.Context(), input); err != nil {
			agentFleetError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"registered": true})
	}))
	mux.HandleFunc("POST /api/v1/nodes/{id}/agent-update", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if !adminOwnerRequired(w, r) {
			return
		}
		var input struct {
			RequestKey string `json:"request_key"`
		}
		if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &input) != nil || !accessPlanUUID.MatchString(input.RequestKey) {
			writeError(w, 400, "invalid agent update request")
			return
		}
		id, err := a.store.StartAgentFleet(r.Context(), r.PathValue("id"), input.RequestKey)
		if err != nil {
			agentFleetError(w, err)
			return
		}
		writeJSON(w, 202, map[string]string{"run_id": id})
	}))
	mux.HandleFunc("POST /api/v1/agent-updates/{id}/pause", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if !adminOwnerRequired(w, r) {
			return
		}
		var input struct {
			Paused bool `json:"paused"`
		}
		if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &input) != nil {
			writeError(w, 400, "invalid pause request")
			return
		}
		if err := a.store.SetAgentFleetPaused(r.Context(), r.PathValue("id"), input.Paused); err != nil {
			agentFleetError(w, err)
			return
		}
		w.WriteHeader(204)
	}))
	mux.HandleFunc("POST /api/v1/agent/update/claim", a.requireAgent(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			UpdaterVersion string `json:"updater_version"`
		}
		if tenantReadJSON(w, r, &input) != nil || input.UpdaterVersion != "0.1.0" {
			writeError(w, 400, "unsupported updater version")
			return
		}
		value, err := a.store.ClaimAgentUpdate(r.Context(), currentNode(r.Context()).ID)
		if err != nil {
			agentFleetError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"assignment": value})
	}))
	mux.HandleFunc("POST /api/v1/agent-update-jobs/{id}/retry", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if !adminOwnerRequired(w, r) {
			return
		}
		if !accessPlanUUID.MatchString(r.PathValue("id")) {
			writeError(w, 400, "invalid job identity")
			return
		}
		if err := a.store.RetryAgentUpdate(r.Context(), r.PathValue("id")); err != nil {
			agentFleetError(w, err)
			return
		}
		w.WriteHeader(204)
	}))
	mux.HandleFunc("POST /api/v1/agent/update/{id}/report", a.requireAgent(func(w http.ResponseWriter, r *http.Request) {
		var input model.AgentUpdateReport
		if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &input) != nil || !accessPlanUUID.MatchString(input.ClaimID) {
			writeError(w, 400, "invalid update report")
			return
		}
		if err := a.store.ReportAgentUpdate(r.Context(), currentNode(r.Context()).ID, r.PathValue("id"), input); err != nil {
			agentFleetError(w, err)
			return
		}
		w.WriteHeader(204)
	}))
}

func (a *application) runAgentFleetController(ctx context.Context) {
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.store.ReconcileAgentFleet(attempt)
		cancel()
		if err != nil {
			log.Print("agent fleet reconciliation unavailable")
		}
	}
}
