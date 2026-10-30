package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/store"
)

func (a *application) prepareRemnawaveSubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminOwnerRequired(w, r) {
		return
	}
	tenant := r.Header.Get("X-Remnawave-Tenant-ID")
	inventorySHA := r.Header.Get("X-Reviewed-Inventory-SHA256")
	settingsSHA := r.Header.Get("X-Reviewed-Settings-SHA256")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !accessPlanUUID.MatchString(tenant) || !reviewedXrayDigest.MatchString(inventorySHA) || !reviewedXrayDigest.MatchString(settingsSHA) || r.Header.Get("X-Remnawave-Mode") != "prepare-held-subscriptions" {
		writeError(w, 400, "explicit held subscription preparation and both reviewed snapshots required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
	if err != nil || remnawave.ValidateSourceJSON(raw, 16<<20) != nil {
		writeError(w, 400, "invalid source subscription settings")
		return
	}
	var header struct {
		Format int    `json:"format"`
		Kind   string `json:"kind"`
	}
	if json.Unmarshal(raw, &header) != nil || header.Format != 1 || header.Kind != "remnawave_subscription_settings_snapshot" {
		writeError(w, 400, "invalid source subscription settings")
		return
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != settingsSHA {
		writeError(w, 400, "reviewed settings digest differs from uploaded bytes")
		return
	}
	out, err := a.store.PrepareImportedSubscriptions(r.Context(), tenant, r.PathValue("id"), inventorySHA, settingsSHA, raw)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrImportedSubscriptionHeld), errors.Is(err, store.ErrImportedSubscriptionIdentity):
			writeError(w, 409, err.Error())
		default:
			remnawaveError(w, err)
		}
		return
	}
	writeJSON(w, 200, out)
}
