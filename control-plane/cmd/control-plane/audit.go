package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"
	"vpn-platform/internal/model"
)

var auditFilterPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,100}$`)

func parseAuditCursor(value string) (*model.AuditCursor, bool) {
	if value == "" {
		return nil, true
	}
	if len(value) > 512 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	var c model.AuditCursor
	if json.Unmarshal(raw, &c) != nil || c.At.IsZero() || !accessPlanUUID.MatchString(c.ID) {
		return nil, false
	}
	return &c, true
}
func (a *application) registerAuditRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/audit-events", a.requireAdmin(a.listAuditEvents))
	mux.HandleFunc("GET /api/v1/audit-event-types", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		types, err := a.store.AuditEventTypes(ctx)
		if err != nil {
			writeError(w, 503, "audit types unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"types": types})
	}))
}
func (a *application) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	tenant, event, actor := q.Get("tenant_id"), q.Get("event_type"), q.Get("actor_type")
	cursor, valid := parseAuditCursor(q.Get("cursor"))
	limit := 50
	if text := q.Get("limit"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > 100 {
			valid = false
		} else {
			limit = n
		}
	}
	if !valid || (tenant != "" && !accessPlanUUID.MatchString(tenant)) || (event != "" && !auditFilterPattern.MatchString(event)) || (actor != "" && !auditFilterPattern.MatchString(actor)) {
		writeError(w, 400, "invalid audit filters or cursor")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, err := a.store.AuditHistory(ctx, tenant, event, actor, cursor, limit)
	if err != nil {
		writeError(w, 503, "audit history unavailable")
		return
	}
	next := ""
	if out.NextCursor != nil {
		raw, _ := json.Marshal(out.NextCursor)
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	writeJSON(w, 200, map[string]any{"events": out.Events, "next_cursor": next})
}
