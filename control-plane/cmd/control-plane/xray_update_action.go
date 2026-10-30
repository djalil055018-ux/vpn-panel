package main

import (
	"errors"
	"net/http"
	"vpn-platform/internal/store"
)

func (a *application) startReviewedXrayUpdate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ReleaseID        string `json:"release_id"`
		RequestKey       string `json:"request_key"`
		AcceptPrerelease bool   `json:"accept_prerelease"`
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &input) != nil || !accessPlanUUID.MatchString(input.ReleaseID) || !accessPlanUUID.MatchString(input.RequestKey) {
		writeError(w, 400, "invalid Xray update request")
		return
	}
	plan, err := a.store.StartReviewedXrayUpdate(r.Context(), r.PathValue("id"), input.ReleaseID, input.RequestKey, input.AcceptPrerelease)
	if err != nil {
		if errors.Is(err, store.ErrAdminPermission) {
			writeError(w, 403, "administrator role required")
			return
		}
		writeError(w, 409, "Xray update unavailable: check release approval, node health, current deployment and prerelease acknowledgement")
		return
	}
	// DesiredStatePreview contains VPN credentials and must never enter this UI.
	writeJSON(w, 202, map[string]any{"plan_id": plan.ID, "node_id": plan.NodeID, "target_version": plan.TargetVersion, "generation": plan.ProposedGeneration, "status": plan.Status, "outcome_status": plan.OutcomeStatus})
}
