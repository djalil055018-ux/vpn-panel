package main

import (
	"errors"
	"net/http"
	"vpn-platform/internal/store"
)

func tenantLimitError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "tenant not found")
	} else if errors.Is(err, store.ErrTenantQuota) {
		writeError(w, 409, "tenant resource limit reached or below current usage")
	} else {
		writeError(w, 503, "tenant limits unavailable")
	}
}
func (a *application) registerTenantLimitRoutes(mux *http.ServeMux) {
	for _, method := range []string{"GET", "PUT"} {
		mux.HandleFunc(method+" /api/v1/tenants/{id}/limits", a.requireAdmin(a.tenantLimits))
	}
	mux.HandleFunc("GET /api/v1/tenant/limits", a.requireTenantAPI("tenant", false, a.tenantLimits))
}
func (a *application) tenantLimits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.PathValue("id")
	if !accessPlanUUID.MatchString(id) {
		writeError(w, 400, "invalid tenant id")
		return
	}
	if r.Method == "GET" {
		v, err := a.store.TenantResourceLimits(r.Context(), id)
		if err != nil {
			tenantLimitError(w, err)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	var v struct {
		MaxClients *int `json:"max_clients"`
		MaxPlans   *int `json:"max_plans"`
	}
	if tenantReadJSON(w, r, &v) != nil || v.MaxClients == nil || v.MaxPlans == nil || *v.MaxClients < 0 || *v.MaxClients > 100000 || *v.MaxPlans < 0 || *v.MaxPlans > 10000 {
		writeError(w, 400, "max_clients 0..100000 and max_plans 0..10000 required; zero is unlimited")
		return
	}
	out, err := a.store.SetTenantResourceLimits(r.Context(), id, *v.MaxClients, *v.MaxPlans)
	if err != nil {
		tenantLimitError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
