package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func tenantReadJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("one object required")
	}
	return nil
}
func (a *application) registerTenantAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tenants/{id}/bot/native", a.requireAdmin(a.configureNativeBot))
	mux.HandleFunc("GET /api/v1/tenants/{id}/api-tokens", a.requireAdmin(a.listTenantAPITokens))
	mux.HandleFunc("POST /api/v1/tenants/{id}/api-tokens", a.requireAdmin(a.createTenantAPIToken))
	mux.HandleFunc("POST /api/v1/tenant-api-tokens/{id}/revoke", a.requireAdmin(a.revokeTenantAPIToken))
	// Tenant credentials are accepted only on this explicit API surface. Adding an
	// admin endpoint never implicitly grants a tenant access to infrastructure.
	for _, route := range []struct {
		pattern, kind string
		operator      bool
		handler       http.HandlerFunc
	}{
		{"GET /api/v1/tenant/me", "", false, a.tenantSelf},
		{"GET /api/v1/tenant/access-plans", "tenant", false, a.listVPNAccessPlans},
		{"POST /api/v1/tenant/access-plans", "tenant", true, a.createVPNAccessPlan},
		{"GET /api/v1/tenant/access-plans/{id}", "plan", false, a.getVPNAccessPlan},
		{"PATCH /api/v1/tenant/access-plans/{id}", "plan", true, a.updateVPNAccessPlan},
		{"DELETE /api/v1/tenant/access-plans/{id}", "plan", true, a.deleteVPNAccessPlan},
		{"POST /api/v1/tenant/access-plans/{id}/services/{service_id}", "plan", true, a.setVPNAccessPlanService},
		{"DELETE /api/v1/tenant/access-plans/{id}/services/{service_id}", "plan", true, a.setVPNAccessPlanService},
		{"POST /api/v1/tenant/access-plans/{id}/clients/{client_id}", "plan", true, a.setVPNClientAccessPlan},
		{"DELETE /api/v1/tenant/access-plans/{id}/clients/{client_id}", "plan", true, a.setVPNClientAccessPlan},
		{"GET /api/v1/tenant/clients", "tenant", false, a.tenantClients},
		{"POST /api/v1/tenant/clients", "tenant", true, a.createVPNClient},
		{"GET /api/v1/tenant/clients/{id}", "client", false, a.tenantClient},
		{"PATCH /api/v1/tenant/clients/{id}", "client", true, a.updateVPNClient},
		{"DELETE /api/v1/tenant/clients/{id}", "client", true, a.deleteVPNClient},
		{"POST /api/v1/tenant/clients/{id}/enable", "client", true, a.enableVPNClient},
		{"POST /api/v1/tenant/clients/{id}/disable", "client", true, a.disableVPNClient},
		{"GET /api/v1/tenant/clients/{id}/subscription", "client", true, a.getVPNClientSubscription},
		{"GET /api/v1/tenant/clients/{id}/connections", "client", true, a.listVPNClientConnections},
		{"POST /api/v1/tenant/clients/{id}/subscription", "client", true, a.createVPNClientSubscription},
		{"POST /api/v1/tenant/clients/{id}/subscription/rotate", "client", true, a.rotateVPNClientSubscription},
		{"GET /api/v1/tenant/services", "", false, a.tenantServices},
	} {
		mux.HandleFunc(route.pattern, a.requireTenantAPI(route.kind, route.operator, route.handler))
	}
}
func (a *application) requireTenantAPI(kind string, operator bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		raw := bearerToken(r)
		if len(raw) != 48 || !strings.HasPrefix(raw, "vpt1_") {
			writeError(w, 401, "invalid tenant credential")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		token, err := a.store.AuthenticateTenantAPIToken(ctx, security.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 401, "invalid tenant credential")
			return
		}
		if err != nil {
			writeError(w, 503, "tenant authentication unavailable")
			return
		}
		if operator && token.Role != "operator" {
			writeError(w, 403, "operator role required")
			return
		}
		ctx = store.WithTenantPrincipal(ctx, token)
		r = r.WithContext(ctx)
		if kind == "tenant" {
			r.SetPathValue("id", token.TenantID)
		} else if kind != "" {
			if !accessPlanUUID.MatchString(r.PathValue("id")) {
				writeError(w, 404, "resource not found")
				return
			}
			owns, err := a.store.TenantOwnsResource(ctx, token.TenantID, kind, r.PathValue("id"))
			if err != nil {
				writeError(w, 503, "resource lookup unavailable")
				return
			}
			if !owns {
				writeError(w, 404, "resource not found")
				return
			}
		}
		for _, target := range []struct{ key, kind string }{{"service_id", "service"}, {"client_id", "client"}} {
			id := r.PathValue(target.key)
			if id == "" {
				continue
			}
			if !accessPlanUUID.MatchString(id) {
				writeError(w, 404, "resource not found")
				return
			}
			owns, err := a.store.TenantOwnsResource(ctx, token.TenantID, target.kind, id)
			if err != nil {
				writeError(w, 503, "resource lookup unavailable")
				return
			}
			if !owns {
				writeError(w, 404, "resource not found")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		next(w, r)
	}
}
func (a *application) createTenantAPIToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid tenant id")
		return
	}
	var input struct {
		Name      string    `json:"name"`
		Role      string    `json:"role"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid token request")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	now := time.Now().UTC()
	if input.Name == "" || len(input.Name) > 100 || (input.Role != "viewer" && input.Role != "operator" && input.Role != "reseller") || input.ExpiresAt.Before(now.Add(time.Hour)) || input.ExpiresAt.After(now.Add(365*24*time.Hour)) {
		writeError(w, 400, "name, viewer/operator/reseller role and expiry between one hour and one year required")
		return
	}
	random, err := security.NewToken(32)
	if err != nil {
		writeError(w, 500, "credential generation failed")
		return
	}
	raw := "vpt1_" + random
	token, err := a.store.CreateTenantAPIToken(r.Context(), r.PathValue("id"), input.Name, input.Role, security.HashToken(raw), input.ExpiresAt)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "tenant not found")
		return
	}
	if errors.Is(err, store.ErrResellerHierarchy) {
		writeError(w, 409, "reseller role requires a top-level tenant")
		return
	}
	if errors.Is(err, store.ErrTenantTokenLimit) {
		writeError(w, 409, "maximum 20 active credentials per tenant")
		return
	}
	if err != nil {
		writeError(w, 500, "credential creation failed")
		return
	}
	writeJSON(w, 201, map[string]any{"credential": token, "token": raw})
}
func (a *application) listTenantAPITokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid tenant id")
		return
	}
	tokens, err := a.store.ListTenantAPITokens(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 503, "credentials unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"credentials": tokens})
}
func (a *application) revokeTenantAPIToken(w http.ResponseWriter, r *http.Request) {
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid credential id")
		return
	}
	token, err := a.store.RevokeTenantAPIToken(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "credential not found")
		return
	}
	if err != nil {
		writeError(w, 500, "credential revocation failed")
		return
	}
	writeJSON(w, 200, token)
}
func (a *application) tenantSelf(w http.ResponseWriter, r *http.Request) {
	token, _ := store.TenantPrincipal(r.Context())
	writeJSON(w, 200, map[string]any{"tenant_id": token.TenantID, "credential_id": token.ID, "role": token.Role, "expires_at": token.ExpiresAt})
}

// Viewer responses deliberately contain no VPN credentials or subscription URLs.
func tenantClientMetadata(client model.VPNClient) map[string]any {
	return map[string]any{"id": client.ID, "tenant_id": client.TenantID, "name": client.Name, "status": client.Status, "effective_status": client.EffectiveStatus, "expires_at": client.ExpiresAt, "created_at": client.CreatedAt, "updated_at": client.UpdatedAt, "remnawave_hold": client.RemnawaveHold}
}
func (a *application) tenantClients(w http.ResponseWriter, r *http.Request) {
	token, _ := store.TenantPrincipal(r.Context())
	clients, err := a.store.ListVPNClients(r.Context(), token.TenantID)
	if err != nil {
		writeError(w, 503, "clients unavailable")
		return
	}
	out := []map[string]any{}
	for _, client := range clients {
		out = append(out, tenantClientMetadata(client))
	}
	writeJSON(w, 200, map[string]any{"clients": out})
}
func (a *application) tenantClient(w http.ResponseWriter, r *http.Request) {
	client, err := a.store.GetVPNClient(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "client not found")
		return
	}
	writeJSON(w, 200, tenantClientMetadata(client))
}
func (a *application) tenantServices(w http.ResponseWriter, r *http.Request) {
	token, _ := store.TenantPrincipal(r.Context())
	rows, err := a.store.Pool.Query(r.Context(), `SELECT id::text,name,protocol,enabled FROM vpn_services WHERE tenant_id=$1::uuid ORDER BY name,id`, token.TenantID)
	if err != nil {
		writeError(w, 503, "services unavailable")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, protocol string
		var enabled bool
		if rows.Scan(&id, &name, &protocol, &enabled) != nil {
			writeError(w, 503, "services unavailable")
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "protocol": protocol, "enabled": enabled})
	}
	if rows.Err() != nil {
		writeError(w, 503, "services unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"services": out})
}
