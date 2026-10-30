package main

import (
	"errors"
	"io"
	"net/http"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

func (a *application) prepareRemnawaveBot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminOwnerRequired(w, r) {
		return
	}
	digest := r.Header.Get("X-Reviewed-Inventory-SHA256")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !reviewedXrayDigest.MatchString(digest) || r.Header.Get("X-Remnawave-Mode") != "prepare-held-bot" {
		writeError(w, 400, "explicit held bot preparation and reviewed inventory required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		writeError(w, 400, "invalid bot preparation request")
		return
	}
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if botbridge.DecodeRequest(raw, &req, "tenant_id") != nil || !accessPlanUUID.MatchString(req.TenantID) {
		writeError(w, 400, "invalid bot preparation request")
		return
	}
	out, err := a.store.PrepareBotBridge(r.Context(), req.TenantID, r.PathValue("id"), digest)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrBotBridgeHeld), errors.Is(err, store.ErrBotBridgeConflict):
			writeError(w, 409, err.Error())
		default:
			remnawaveError(w, err)
		}
		return
	}
	writeJSON(w, 200, out)
}
