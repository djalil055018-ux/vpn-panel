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

func (a *application) renameNode(w http.ResponseWriter, r *http.Request) {
	if principal, ok := store.AdminPrincipal(r.Context()); ok && principal.Account.Role != "owner" {
		writeError(w, http.StatusForbidden, "owner role required")
		return
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) {
		writeError(w, http.StatusBadRequest, "invalid node identity")
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if readErr != nil || botbridge.DecodeRequest(raw, &input, "name") != nil {
		writeError(w, http.StatusBadRequest, "a single node name field is required")
		return
	}
	name, err := store.NormalizeNodeName(input.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "node name must contain 1 to 80 characters without control characters")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := a.store.RenameNode(ctx, r.PathValue("id"), name)
	switch {
	case errors.Is(err, store.ErrAdminPermission):
		writeError(w, http.StatusForbidden, "owner role required")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "node not found")
	case errors.Is(err, store.ErrNodeRetired):
		writeError(w, http.StatusConflict, "retired nodes cannot be renamed")
	case errors.Is(err, store.ErrNodeNameInvalid):
		writeError(w, http.StatusBadRequest, "node name is invalid")
	case errors.Is(err, store.ErrNodeNameConflict):
		writeError(w, http.StatusConflict, "a node with this name already exists")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "node was not renamed")
	default:
		writeJSON(w, http.StatusOK, result)
	}
}
