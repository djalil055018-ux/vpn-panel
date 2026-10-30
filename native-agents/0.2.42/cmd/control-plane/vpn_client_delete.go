package main

import (
	"context"
	"errors"
	"net/http"
	"time"
	"vpn-platform/internal/store"
)

func (a *application) deleteVPNClient(w http.ResponseWriter, r *http.Request) {
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid client identity")
		return
	}
	var input struct {
		ConfirmName string `json:"confirm_name"`
	}
	if tenantReadJSON(w, r, &input) != nil || input.ConfirmName == "" || len(input.ConfirmName) > 2048 {
		writeError(w, 400, "exact client name confirmation required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := a.store.DeleteVPNClient(ctx, r.PathValue("id"), input.ConfirmName)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "client not found")
	case errors.Is(err, store.ErrClientDeleteConfirmation):
		writeError(w, 409, "client name changed or confirmation differs")
	case errors.Is(err, store.ErrImportedClientDeleteOwner):
		writeError(w, 403, "owner role required for imported client")
	case err != nil:
		writeError(w, 409, "client was not deleted; affected node configuration could not be rebuilt")
	default:
		writeJSON(w, http.StatusAccepted, result)
	}
}
