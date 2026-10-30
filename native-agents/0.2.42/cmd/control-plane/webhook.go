package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
	"vpn-platform/internal/webhook"
)

func (a *application) registerWebhookRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /api/v1/tenants/{id}/webhooks", a.listWebhooks}, {"POST /api/v1/tenants/{id}/webhooks", a.createWebhook},
		{"PATCH /api/v1/webhooks/{id}", a.setWebhookEnabled}, {"GET /api/v1/tenants/{id}/webhook-deliveries", a.listWebhookDeliveries}, {"POST /api/v1/webhook-deliveries/{id}/retry", a.retryWebhookDelivery},
		{"DELETE /api/v1/webhooks/{id}", a.deleteWebhook},
	} {
		handler := route.handler
		mux.HandleFunc(route.pattern, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if !accessPlanUUID.MatchString(r.PathValue("id")) {
				writeError(w, 400, "invalid id")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			handler(w, r.WithContext(ctx))
		}))
	}
	mux.HandleFunc("GET /api/v1/webhooks/status", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		queue, err := a.store.WebhookQueueStatus(r.Context())
		if err != nil {
			webhookError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"queue": queue, "configured": webhook.MasterReady(os.Getenv("WEBHOOK_ENCRYPTION_KEY")), "events": []string{"billing.invoice_paid", "billing.invoice_voided"}})
	}))
}
func webhookError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "webhook resource not found")
	} else if errors.Is(err, store.ErrWebhookLimit) || errors.Is(err, store.ErrBillingConflict) {
		writeError(w, 409, "webhook operation conflicts with current state")
	} else {
		writeError(w, 503, "webhook operation unavailable")
	}
}
func (a *application) createWebhook(w http.ResponseWriter, r *http.Request) {
	master := os.Getenv("WEBHOOK_ENCRYPTION_KEY")
	if !webhook.MasterReady(master) {
		writeError(w, 503, "outgoing webhooks are not configured")
		return
	}
	var input struct {
		Name   string   `json:"name"`
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid webhook request")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	seen := map[string]bool{}
	valid := len(input.Events) >= 1 && len(input.Events) <= 2
	for _, event := range input.Events {
		if seen[event] || (event != "billing.invoice_paid" && event != "billing.invoice_voided") {
			valid = false
		}
		seen[event] = true
	}
	if input.Name == "" || len(input.Name) > 100 || !webhook.ValidateURL(input.URL) || !valid {
		writeError(w, 400, "name, public HTTPS URL on port 443 without credentials/query/fragment, and supported events required")
		return
	}
	id, err := webhook.NewID()
	if err != nil {
		webhookError(w, err)
		return
	}
	secret, err := security.NewToken(32)
	if err != nil {
		webhookError(w, err)
		return
	}
	encrypted, err := webhook.Encrypt(master, id, secret)
	if err != nil {
		webhookError(w, err)
		return
	}
	out, err := a.store.CreateWebhookEndpoint(r.Context(), model.WebhookEndpoint{ID: id, TenantID: r.PathValue("id"), Name: input.Name, URL: input.URL, Events: input.Events}, encrypted)
	if err != nil {
		webhookError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"endpoint": out, "signing_secret": secret})
}
func (a *application) listWebhooks(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.ListWebhookEndpoints(r.Context(), r.PathValue("id"))
	if err != nil {
		webhookError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"endpoints": out})
}
func (a *application) setWebhookEnabled(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if tenantReadJSON(w, r, &input) != nil || input.Enabled == nil {
		writeError(w, 400, "enabled is required")
		return
	}
	if *input.Enabled && !webhook.MasterReady(os.Getenv("WEBHOOK_ENCRYPTION_KEY")) {
		writeError(w, 503, "outgoing webhooks are not configured")
		return
	}
	out, err := a.store.SetWebhookEnabled(r.Context(), r.PathValue("id"), *input.Enabled)
	if err != nil {
		webhookError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (a *application) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.ListWebhookDeliveries(r.Context(), r.PathValue("id"))
	if err != nil {
		webhookError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deliveries": out})
}
func (a *application) retryWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	if err := a.store.RetryWebhookDelivery(r.Context(), r.PathValue("id")); err != nil {
		webhookError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *application) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteWebhookEndpoint(r.Context(), r.PathValue("id")); err != nil {
		webhookError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
