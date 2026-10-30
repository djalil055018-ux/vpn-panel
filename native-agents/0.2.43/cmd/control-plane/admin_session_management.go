package main

import (
	"net/http"
	"vpn-platform/internal/store"
)

func (a *application) registerAdminSessionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/me/sessions", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := store.AdminPrincipal(r.Context()); !ok {
			writeError(w, 401, "personal session required")
			return
		}
		sessions, err := a.store.ListOwnAdminSessions(r.Context())
		if err != nil {
			adminAccountError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"sessions": sessions})
	}))
	revoke := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := store.AdminPrincipal(r.Context()); !ok {
			writeError(w, 401, "personal session required")
			return
		}
		id := r.PathValue("id")
		if id != "" && !accessPlanUUID.MatchString(id) {
			writeError(w, 400, "invalid session identifier")
			return
		}
		if _, err := a.store.RevokeOwnAdminSessions(r.Context(), id); err != nil {
			adminAccountError(w, err)
			return
		}
		w.WriteHeader(204)
	}
	mux.HandleFunc("DELETE /api/v1/admin/me/sessions", a.requireAdmin(revoke))
	mux.HandleFunc("DELETE /api/v1/admin/me/sessions/{id}", a.requireAdmin(revoke))
}
