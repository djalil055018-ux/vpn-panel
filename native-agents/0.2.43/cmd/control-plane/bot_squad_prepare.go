package main

import (
	"errors"
	"io"
	"net/http"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

type botSquadPreparationRequest struct {
	TenantID     string `json:"tenant_id"`
	RevisionID   string `json:"revision_id"`
	BundleSHA256 string `json:"bundle_sha256"`
}

func decodeBotSquadPreparation(raw []byte) (req botSquadPreparationRequest, err error) {
	err = botbridge.DecodeRequest(raw, &req, "tenant_id", "revision_id", "bundle_sha256")
	if err != nil || !accessPlanUUID.MatchString(req.TenantID) || !accessPlanUUID.MatchString(req.RevisionID) || !reviewedXrayDigest.MatchString(req.BundleSHA256) {
		return req, botbridge.ErrRequest
	}
	return req, nil
}
func (a *application) prepareRemnawaveBotSquads(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminOwnerRequired(w, r) {
		return
	}
	digest := r.Header.Get("X-Reviewed-Inventory-SHA256")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !reviewedXrayDigest.MatchString(digest) || r.Header.Get("X-Remnawave-Mode") != "prepare-held-bot-squads" {
		writeError(w, 400, "explicit held squad preparation and reviewed inventory required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		writeError(w, 400, "invalid squad preparation request")
		return
	}
	req, err := decodeBotSquadPreparation(raw)
	if err != nil {
		writeError(w, 400, "invalid squad preparation request")
		return
	}
	out, err := a.store.PrepareBotSquadPlans(r.Context(), req.TenantID, r.PathValue("id"), digest, req.RevisionID, req.BundleSHA256)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrBotBridgeHeld), errors.Is(err, store.ErrBotBridgeConflict), errors.Is(err, store.ErrImportedSubscriptionHeld):
			writeError(w, 409, err.Error())
		default:
			remnawaveError(w, err)
		}
		return
	}
	writeJSON(w, 200, out)
}
