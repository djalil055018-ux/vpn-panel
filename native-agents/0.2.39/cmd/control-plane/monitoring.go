package main

import (
	"context"
	"errors"
	"net/http"
	"time"
	"vpn-platform/internal/store"
)

func (a *application) registerMonitoringRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/operations/incidents", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out, err := a.store.MonitoringStatus(ctx)
		if err != nil {
			writeError(w, 503, "incident history unavailable")
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /api/v1/operations/incidents/{id}/acknowledge", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !accessPlanUUID.MatchString(r.PathValue("id")) {
			writeError(w, 400, "invalid incident id")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out, err := a.store.AcknowledgeMonitoringIncident(ctx, r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 404, "open incident not found")
			return
		}
		if err != nil {
			writeError(w, 503, "acknowledgement unavailable")
			return
		}
		writeJSON(w, 200, out)
	}))
}
