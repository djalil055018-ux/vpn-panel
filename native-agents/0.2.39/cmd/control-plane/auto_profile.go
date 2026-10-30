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

func (a *application) registerAutoProfileRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /api/v1/tenants/{id}/auto-profile", a.getAutoProfile},
		{"PUT /api/v1/tenants/{id}/auto-profile", a.setAutoProfile},
	} {
		handler := route.handler
		mux.HandleFunc(route.pattern, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if !accessPlanUUID.MatchString(r.PathValue("id")) {
				writeError(w, 400, "invalid tenant id")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			handler(w, r.WithContext(ctx))
		}))
	}
	mux.HandleFunc("GET /api/v1/tenant/auto-profile", a.requireTenantAPI("tenant", false, a.getAutoProfile))
	mux.HandleFunc("PUT /api/v1/tenant/auto-profile", a.requireTenantAPI("tenant", true, a.setAutoProfile))
}

func (a *application) getAutoProfile(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetAutoProfileSettings(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "tenant not found")
		return
	}
	if err != nil {
		writeError(w, 503, "automatic profile settings unavailable")
		return
	}
	writeJSON(w, 200, settings)
}

func (a *application) setAutoProfile(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled      *bool   `json:"enabled"`
		Name         *string `json:"name"`
		RussiaDirect *bool   `json:"russia_direct"`
	}
	if tenantReadJSON(w, r, &input) != nil || input.Enabled == nil || input.Name == nil || input.RussiaDirect == nil {
		writeError(w, 400, "enabled, name and russia_direct are required")
		return
	}
	name := strings.TrimSpace(*input.Name)
	if !model.ValidAutoProfileName(name) {
		writeError(w, 400, "name must contain 1 to 80 characters in one line")
		return
	}
	settings, err := a.store.SetAutoProfileSettings(r.Context(), r.PathValue("id"), model.AutoProfileSettings{Enabled: *input.Enabled, Name: name, RussiaDirect: *input.RussiaDirect})
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "tenant not found")
		return
	}
	if err != nil {
		writeError(w, 503, "could not save automatic profile settings")
		return
	}
	writeJSON(w, 200, settings)
}
