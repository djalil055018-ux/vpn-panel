package main

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/store"
)

func (a *application) registerRemnawaveRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/remnawave/preview", a.requireAdmin(a.previewRemnawave))
	mux.HandleFunc("POST /api/v1/tenants/{id}/remnawave-imports", a.requireAdmin(a.stageRemnawave))
	mux.HandleFunc("GET /api/v1/remnawave/imports", a.requireAdmin(a.listRemnawave))
	mux.HandleFunc("GET /api/v1/remnawave/imports/{id}/clients", a.requireAdmin(a.listRemnawaveClients))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/delta-preview", a.requireAdmin(a.previewRemnawaveDelta))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/prepare-quota", a.requireAdmin(a.prepareRemnawaveQuota))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/delta-apply", a.requireAdmin(a.applyRemnawaveDelta))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/prepare-xray-node", a.requireAdmin(a.prepareRemnawaveXrayNode))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/prepare-tls", a.requireAdmin(a.prepareRemnawaveTLS))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/prepare-subscriptions", a.requireAdmin(a.prepareRemnawaveSubscriptions))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/prepare-bot-squads", a.requireAdmin(a.prepareRemnawaveBotSquads))
	mux.HandleFunc("POST /api/v1/remnawave/imports/{id}/prepare-bot", a.requireAdmin(a.prepareRemnawaveBot))
}
func readRemnawave(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, remnawave.MaxInventoryBytes))
	if err != nil {
		writeError(w, 400, "inventory exceeds the supported size or cannot be read")
		return nil, false
	}
	return raw, true
}
func remnawaveError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, remnawave.ErrInventory), errors.Is(err, remnawave.ErrDeltaSource), errors.Is(err, store.ErrRemnawaveReview):
		writeError(w, 400, err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "migration target unavailable")
	case errors.Is(err, store.ErrRemnawaveConflict), errors.Is(err, store.ErrRemnawaveBase), errors.Is(err, store.ErrTenantQuota), errors.Is(err, store.ErrTrafficPolicyConflict):
		writeError(w, 409, err.Error())
	default:
		writeError(w, 503, "migration staging unavailable") // never emit parser/SQL payloads
	}
}
func (a *application) applyRemnawaveDelta(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	tenant := r.Header.Get("X-Remnawave-Tenant-ID")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !accessPlanUUID.MatchString(tenant) || r.Header.Get("X-Remnawave-Mode") != "apply-held-delta" {
		writeError(w, 400, "explicit held delta mode and target tenant required")
		return
	}
	raw, ok := readRemnawave(w, r)
	if !ok {
		return
	}
	result, err := a.store.ApplyRemnawaveHeldDelta(r.Context(), r.PathValue("id"), tenant, r.Header.Get("X-Base-Inventory-SHA256"), r.Header.Get("X-Reviewed-Inventory-SHA256"), raw)
	if err != nil {
		remnawaveError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (a *application) prepareRemnawaveQuota(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	tenant := r.Header.Get("X-Remnawave-Tenant-ID")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !accessPlanUUID.MatchString(tenant) || r.Header.Get("X-Remnawave-Mode") != "prepare-held-quota" {
		writeError(w, 400, "explicit held quota mode and target tenant required")
		return
	}
	result, err := a.store.PrepareRemnawaveNoResetQuota(r.Context(), r.PathValue("id"), tenant, r.Header.Get("X-Reviewed-Inventory-SHA256"))
	if err != nil {
		remnawaveError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (a *application) previewRemnawave(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	raw, ok := readRemnawave(w, r)
	if !ok {
		return
	}
	_, report, err := remnawave.Parse(raw)
	if err != nil {
		remnawaveError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"report": report, "stage_ready": true, "cutover_ready": false})
}
func (a *application) previewRemnawaveDelta(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	tenant := r.Header.Get("X-Remnawave-Tenant-ID")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !accessPlanUUID.MatchString(tenant) {
		writeError(w, 400, "migration id and target tenant required")
		return
	}
	raw, ok := readRemnawave(w, r)
	if !ok {
		return
	}
	report, err := a.store.PreviewRemnawaveDelta(r.Context(), r.PathValue("id"), tenant, raw)
	if err != nil {
		remnawaveError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"delta": report, "source_modified": false, "target_modified": false, "cutover_ready": false})
}
func (a *application) stageRemnawave(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) || r.Header.Get("X-Remnawave-Mode") != "stage-held" {
		writeError(w, 400, "explicit held staging mode and target tenant required")
		return
	}
	raw, ok := readRemnawave(w, r)
	if !ok {
		return
	}
	result, created, err := a.store.StageRemnawaveInventory(r.Context(), r.PathValue("id"), raw, r.Header.Get("X-Reviewed-Inventory-SHA256"))
	if err != nil {
		remnawaveError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, map[string]any{"import": result, "created": created, "cutover_ready": false})
}
func (a *application) listRemnawave(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	items, err := a.store.ListRemnawaveImports(r.Context())
	if err != nil {
		remnawaveError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"imports": items})
}
func (a *application) listRemnawaveClients(w http.ResponseWriter, r *http.Request) {
	if !adminOwnerRequired(w, r) {
		return
	}
	after := int64(0)
	var err error
	if v := r.URL.Query().Get("after"); v != "" {
		after, err = strconv.ParseInt(v, 10, 64)
	}
	if err != nil || after < 0 || !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid migration cursor")
		return
	}
	items, err := a.store.RemnawaveImportClients(r.Context(), r.PathValue("id"), after, 250)
	if err != nil {
		remnawaveError(w, err)
		return
	}
	var next *int64
	if len(items) == 250 {
		v := items[len(items)-1].SourceID
		next = &v
	}
	writeJSON(w, 200, map[string]any{"clients": items, "next_cursor": next})
}
