package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func (a *application) registerCascadeRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /api/v1/tenants/{id}/cascades", a.listVPNCascades},
		{"POST /api/v1/tenants/{id}/cascades", a.createVPNCascade},
		{"GET /api/v1/vpn-cascades/{id}", a.getVPNCascade},
		{"PUT /api/v1/vpn-cascades/{id}", a.updateVPNCascade},
		{"DELETE /api/v1/vpn-cascades/{id}", a.deleteVPNCascade},
	} {
		handler := route.handler
		mux.HandleFunc(route.pattern, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if !accessPlanUUID.MatchString(r.PathValue("id")) {
				writeError(w, 400, "valid resource id required")
				return
			}
			r.SetPathValue("id", strings.ToLower(r.PathValue("id")))
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			handler(w, r.WithContext(ctx))
		}))
	}
}

func writeCascadeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "cascade, group or server not found")
	case errors.Is(err, store.ErrVPNCascade), errors.Is(err, store.ErrVPNCascadeIdentity), errors.Is(err, store.ErrNodeRuntime):
		writeError(w, 409, "cascade needs two distinct VLESS TCP REALITY servers, Agent 0.2.34 or newer, Xray 26.9.9 or newer and a free entry port; no changes committed")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, 503, "cascade operation timed out")
	default:
		writeError(w, 500, "cascade operation failed; no partial change committed")
	}
}

func readCascadeInput(w http.ResponseWriter, r *http.Request) (model.VPNCascadeInput, bool) {
	var input model.VPNCascadeInput
	if err := tenantReadJSON(w, r, &input); err != nil {
		writeError(w, 400, "invalid cascade definition; expected one JSON object without extra fields")
		return input, false
	}
	input.PlanID = strings.ToLower(input.PlanID)
	input.EntryServiceID = strings.ToLower(input.EntryServiceID)
	input.ExitServiceID = strings.ToLower(input.ExitServiceID)
	return input, true
}

func (a *application) listVPNCascades(w http.ResponseWriter, r *http.Request) {
	items, err := a.store.ListVPNCascades(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCascadeError(w, err)
		return
	}
	views := []model.VPNCascadeView{}
	for _, item := range items {
		view, err := a.store.VPNCascadeStatus(r.Context(), item.ID)
		if err != nil {
			writeCascadeError(w, err)
			return
		}
		views = append(views, view)
	}
	writeJSON(w, 200, map[string]any{"cascades": views, "minimum_agent": model.XrayCascadeMinimumAgent, "mode": "separate_profile", "protocol": "vless", "transport": "tcp", "security": "reality"})
}
func (a *application) getVPNCascade(w http.ResponseWriter, r *http.Request) {
	view, err := a.store.VPNCascadeStatus(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCascadeError(w, err)
		return
	}
	writeJSON(w, 200, view)
}
func (a *application) createVPNCascade(w http.ResponseWriter, r *http.Request) {
	input, ok := readCascadeInput(w, r)
	if !ok {
		return
	}
	result, err := a.store.PutVPNCascade(r.Context(), r.PathValue("id"), "", input)
	if err != nil {
		writeCascadeError(w, err)
		return
	}
	writeJSON(w, 201, result)
}
func (a *application) updateVPNCascade(w http.ResponseWriter, r *http.Request) {
	input, ok := readCascadeInput(w, r)
	if !ok {
		return
	}
	prior, err := a.store.GetVPNCascade(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCascadeError(w, err)
		return
	}
	result, err := a.store.PutVPNCascade(r.Context(), prior.TenantID, prior.ID, input)
	if err != nil {
		writeCascadeError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (a *application) deleteVPNCascade(w http.ResponseWriter, r *http.Request) {
	result, err := a.store.DeleteVPNCascade(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCascadeError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
