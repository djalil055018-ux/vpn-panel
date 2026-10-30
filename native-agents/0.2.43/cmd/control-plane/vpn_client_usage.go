package main

import (
	"errors"
	"net/http"

	"vpn-platform/internal/store"
)

func (a *application) registerVPNClientUsageRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/vpn-clients/{id}/usage", a.requireAdmin(a.getVPNClientUsage))
	mux.HandleFunc("PUT /api/v1/vpn-clients/{id}/limits", a.requireAdmin(a.setVPNClientLimits))
	mux.HandleFunc("GET /api/v1/tenant/clients/{id}/usage", a.requireTenantAPI("client", false, a.getVPNClientUsage))
	mux.HandleFunc("PUT /api/v1/tenant/clients/{id}/limits", a.requireTenantAPI("client", true, a.setVPNClientLimits))
	mux.HandleFunc("PUT /api/v1/vpn-clients/{id}/continuous-limit", a.requireAdmin(a.setVPNClientContinuousLimit))
	mux.HandleFunc("PUT /api/v1/tenant/clients/{id}/continuous-limit", a.requireTenantAPI("client", true, a.setVPNClientContinuousLimit))
}

func clientUsageError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrTrafficPolicyConflict) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "vpn client not found")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "client usage unavailable")
}

func (a *application) setVPNClientContinuousLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid client id")
		return
	}
	var input struct {
		LimitBytes *int64 `json:"limit_bytes"`
	}
	if tenantReadJSON(w, r, &input) != nil || input.LimitBytes == nil || *input.LimitBytes < 0 || *input.LimitBytes > 9000000000000000 {
		writeError(w, 400, "limit_bytes 0..9000000000000000 required; zero is unlimited")
		return
	}
	usage, err := a.store.SetVPNClientContinuousLimit(r.Context(), r.PathValue("id"), *input.LimitBytes)
	if err != nil {
		clientUsageError(w, err)
		return
	}
	writeJSON(w, 200, usage)
}

func (a *application) getVPNClientUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, http.StatusBadRequest, "invalid client id")
		return
	}
	usage, err := a.store.VPNClientUsage(r.Context(), r.PathValue("id"))
	if err != nil {
		clientUsageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

func (a *application) setVPNClientLimits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, http.StatusBadRequest, "invalid client id")
		return
	}
	var input struct {
		MonthlyBytes *int64 `json:"monthly_bytes"`
		DeviceLimit  *int   `json:"device_limit"`
	}
	if tenantReadJSON(w, r, &input) != nil || input.MonthlyBytes == nil || input.DeviceLimit == nil || *input.MonthlyBytes < 0 || *input.MonthlyBytes > 9000000000000000 || *input.DeviceLimit < 0 || *input.DeviceLimit > 1000 {
		writeError(w, http.StatusBadRequest, "monthly_bytes 0..9000000000000000 and device_limit 0..1000 required; zero is unlimited")
		return
	}
	usage, err := a.store.SetVPNClientLimits(r.Context(), r.PathValue("id"), *input.MonthlyBytes, *input.DeviceLimit)
	if err != nil {
		clientUsageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, usage)
}
