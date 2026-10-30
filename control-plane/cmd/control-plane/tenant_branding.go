package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func validBranding(b model.TenantBranding) bool {
	for _, field := range []struct {
		value string
		max   int
	}{{b.DisplayName, 80}, {b.Tagline, 160}, {b.SupportLabel, 40}, {b.SupportURL, 500}} {
		if !utf8.ValidString(field.value) || utf8.RuneCountInString(field.value) > field.max {
			return false
		}
		for _, r := range field.value {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	if b.DisplayName == "" {
		return false
	}
	switch b.Accent {
	case "blue", "violet", "teal", "amber", "rose":
	default:
		return false
	}
	if (b.SupportURL == "") != (b.SupportLabel == "") {
		return false
	}
	if b.SupportURL != "" {
		u, err := url.Parse(b.SupportURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(b.SupportURL, "\\ \t\r\n") {
			return false
		}
	}
	return true
}
func (a *application) registerTenantBrandingRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{{"GET /api/v1/tenants/{id}/branding", a.getTenantBranding}, {"PUT /api/v1/tenants/{id}/branding", a.setTenantBranding}} {
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
	mux.HandleFunc("GET /api/v1/tenant/branding", a.requireTenantAPI("tenant", false, a.getTenantBranding))
	mux.HandleFunc("PUT /api/v1/tenant/branding", a.requireTenantAPI("tenant", true, a.setTenantBranding))
}
func (a *application) getTenantBranding(w http.ResponseWriter, r *http.Request) {
	b, err := a.store.GetTenantBranding(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "tenant not found")
		return
	}
	if err != nil {
		writeError(w, 503, "branding unavailable")
		return
	}
	writeJSON(w, 200, b)
}
func (a *application) setTenantBranding(w http.ResponseWriter, r *http.Request) {
	var input struct {
		DisplayName  string `json:"display_name"`
		Tagline      string `json:"tagline"`
		SupportLabel string `json:"support_label"`
		SupportURL   string `json:"support_url"`
		Accent       string `json:"accent"`
	}
	if tenantReadJSON(w, r, &input) != nil {
		writeError(w, 400, "invalid branding request")
		return
	}
	b := model.TenantBranding{DisplayName: strings.TrimSpace(input.DisplayName), Tagline: strings.TrimSpace(input.Tagline), SupportLabel: strings.TrimSpace(input.SupportLabel), SupportURL: strings.TrimSpace(input.SupportURL), Accent: input.Accent}
	if !validBranding(b) {
		writeError(w, 400, "invalid branding; HTTPS support URL and matching label required")
		return
	}
	b, err := a.store.SetTenantBranding(r.Context(), r.PathValue("id"), b)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "tenant not found")
		return
	}
	if err != nil {
		writeError(w, 503, "branding update failed")
		return
	}
	writeJSON(w, 200, b)
}
