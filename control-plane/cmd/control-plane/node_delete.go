package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

func (a *application) deleteNode(w http.ResponseWriter, r *http.Request) {
	if principal, ok := store.AdminPrincipal(r.Context()); ok && principal.Account.Role != "owner" {
		writeError(w, 403, "owner role required")
		return
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, 400, "invalid node identity")
		return
	}
	var input struct {
		ConfirmName        string `json:"confirm_name"`
		ServerStopped      bool   `json:"server_stopped"`
		DecommissionOnline bool   `json:"decommission_online"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if readErr != nil || botbridge.DecodeRequest(raw, &input, "confirm_name", "server_stopped", "decommission_online") != nil || input.ConfirmName == "" || len(input.ConfirmName) > 2048 || (!input.ServerStopped && !input.DecommissionOnline) {
		writeError(w, 400, "exact node name and a safe shutdown option are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := a.store.DeleteNodeWithOptions(ctx, r.PathValue("id"), input.ConfirmName, input.ServerStopped, input.DecommissionOnline)
	switch {
	case errors.Is(err, store.ErrAdminPermission):
		writeError(w, 403, "owner role required")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "node not found")
	case errors.Is(err, store.ErrNodeDeleteConfirmation):
		writeError(w, 409, "node name changed or confirmation differs")
	case errors.Is(err, store.ErrNodeDeleteBusy):
		writeError(w, 409, "node is still applying the empty VPN configuration or has unresolved work")
	case err != nil:
		writeError(w, 409, "node was not deleted")
	default:
		if result.Decommissioning {
			writeJSON(w, http.StatusAccepted, result)
		} else {
			writeJSON(w, http.StatusOK, result)
		}
	}
}
