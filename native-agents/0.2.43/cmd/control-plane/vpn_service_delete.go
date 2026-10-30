package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

func (a *application) deleteVPNService(w http.ResponseWriter, r *http.Request) {
	if principal, ok := store.AdminPrincipal(r.Context()); ok && principal.Account.Role != "owner" {
		writeError(w, http.StatusForbidden, "owner role required")
		return
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, http.StatusBadRequest, "invalid service identity")
		return
	}
	var input struct {
		ConfirmName string `json:"confirm_name"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if readErr != nil || botbridge.DecodeRequest(raw, &input, "confirm_name") != nil || strings.TrimSpace(input.ConfirmName) == "" || len(input.ConfirmName) > 2048 {
		writeError(w, http.StatusBadRequest, "exact service name confirmation required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := a.store.DeleteVPNServiceAndRebuild(ctx, r.PathValue("id"), strings.TrimSpace(input.ConfirmName))
	switch {
	case errors.Is(err, store.ErrAdminPermission):
		writeError(w, http.StatusForbidden, "owner role required")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "vpn service not found")
	case errors.Is(err, store.ErrVPNServiceDeleteConfirmation):
		writeError(w, http.StatusConflict, "service name changed or confirmation differs")
	case errors.Is(err, store.ErrVPNServiceDeleteProtected):
		writeError(w, http.StatusConflict, "remove this service from cascades or immutable imported subscriptions first")
	case errors.Is(err, store.ErrNodeRetired):
		writeError(w, http.StatusConflict, "service belongs to a retired node")
	case err != nil:
		writeError(w, http.StatusConflict, "service was not deleted; check node deployment and dependencies")
	default:
		writeJSON(w, http.StatusAccepted, result)
	}
}
