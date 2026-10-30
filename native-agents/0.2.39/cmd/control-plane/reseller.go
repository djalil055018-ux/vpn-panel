package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func (a *application) requireReseller(next http.HandlerFunc) http.HandlerFunc {
	return a.requireTenantAPI("", false, func(w http.ResponseWriter, r *http.Request) {
		t, _ := store.TenantPrincipal(r.Context())
		if t.Role != "reseller" {
			writeError(w, 403, "reseller role required")
			return
		}
		for _, key := range []string{"id", "token_id"} {
			if value := r.PathValue(key); value != "" && !accessPlanUUID.MatchString(value) {
				writeError(w, 404, "child resource not found")
				return
			}
		}
		next(w, r)
	})
}
func (a *application) registerResellerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/tenant/children", a.requireReseller(a.listResellerChildren))
	mux.HandleFunc("POST /api/v1/tenant/children", a.requireReseller(a.createResellerChild))
	mux.HandleFunc("GET /api/v1/tenant/children/{id}/api-tokens", a.requireReseller(a.listResellerChildTokens))
	mux.HandleFunc("POST /api/v1/tenant/children/{id}/api-tokens", a.requireReseller(a.createResellerChildToken))
	mux.HandleFunc("POST /api/v1/tenant/children/{id}/api-tokens/{token_id}/revoke", a.requireReseller(a.revokeResellerChildToken))
	mux.HandleFunc("GET /api/v1/tenants/{id}/children", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !accessPlanUUID.MatchString(r.PathValue("id")) {
			writeError(w, 400, "invalid tenant id")
			return
		}
		a.listResellerChildren(w, r)
	}))
}
func resellerError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "child resource not found")
	} else if errors.Is(err, store.ErrResellerLimit) || errors.Is(err, store.ErrResellerHierarchy) || errors.Is(err, store.ErrTenantTokenLimit) {
		writeError(w, 409, "reseller hierarchy, expiry or resource limit conflict")
	} else {
		writeError(w, 503, "reseller operation unavailable")
	}
}
func (a *application) listResellerChildren(w http.ResponseWriter, r *http.Request) {
	parent := r.PathValue("id")
	if t, ok := store.TenantPrincipal(r.Context()); ok {
		parent = t.TenantID
	}
	out, err := a.store.ListResellerChildren(r.Context(), parent)
	if err != nil {
		resellerError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"children": out})
}
func (a *application) createResellerChild(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid child request")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 100 {
		writeError(w, 400, "name between 1 and 100 bytes required")
		return
	}
	out, err := a.store.CreateResellerChild(r.Context(), input.Name)
	if err != nil {
		resellerError(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (a *application) listResellerChildTokens(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.ListResellerChildTokens(r.Context(), r.PathValue("id"))
	if err != nil {
		resellerError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"credentials": out})
}
func (a *application) createResellerChildToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name      string    `json:"name"`
		Role      string    `json:"role"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid child credential request")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	parent, _ := store.TenantPrincipal(r.Context())
	now := time.Now().UTC()
	if input.Name == "" || len(input.Name) > 100 || (input.Role != "viewer" && input.Role != "operator") || input.ExpiresAt.Before(now.Add(time.Hour)) || input.ExpiresAt.After(parent.ExpiresAt) {
		writeError(w, 400, "viewer/operator role, name and expiry within parent credential lifetime required")
		return
	}
	random, err := security.NewToken(32)
	if err != nil {
		resellerError(w, err)
		return
	}
	raw := "vpt1_" + random
	out, err := a.store.CreateResellerChildToken(r.Context(), r.PathValue("id"), input.Name, input.Role, security.HashToken(raw), input.ExpiresAt)
	if err != nil {
		resellerError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"credential": out, "token": raw})
}
func (a *application) revokeResellerChildToken(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.RevokeResellerChildToken(r.Context(), r.PathValue("id"), r.PathValue("token_id"))
	if err != nil {
		resellerError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
