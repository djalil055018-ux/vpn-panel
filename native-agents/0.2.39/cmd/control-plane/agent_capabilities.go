package main

import (
	"errors"
	"net/http"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func (a *application) registerAgentCapabilityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/agent/capabilities", a.agentCapabilities)
	mux.HandleFunc("GET /api/v1/agent/bootstrap-info", a.agentBootstrapInfo)
}

// This contract describes guarded agent provisioning and telemetry, not the
// availability of every service/UI workflow for a runtime.
func (a *application) agentCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"format": 1, "runtime_selection": true, "bootstrap_inspection": true,
		"traffic_address_availability": true,
		"runtimes": map[string]any{
			"pptp":      map[string]any{"minimum_agent": "0.2.30", "provisioning": true, "legacy": true, "ipv4_only": true},
			"wireguard": map[string]any{"minimum_agent": "0.2.28", "provisioning": true},
			"openvpn":   map[string]any{"minimum_agent": "0.2.27", "provisioning": true},
			"xray":      map[string]any{"minimum_agent": "0.2.23", "provisioning": true},
			"hysteria2": map[string]any{"minimum_agent": store.HysteriaOperationalMinimumAgent, "provisioning": true},
		},
	})
}

func (a *application) agentBootstrapInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "bootstrap token required")
		return
	}
	info, err := a.store.InspectNodeBootstrap(r.Context(), security.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid or already used bootstrap token")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "bootstrap inspection unavailable")
		return
	}
	writeJSON(w, http.StatusOK, info)
}
