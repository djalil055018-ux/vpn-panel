package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func (a *application) registerNodeRebootRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/nodes/{id}/reboot", a.requireAdmin(a.requestNodeReboot))
	mux.HandleFunc("POST /api/v1/agent/node-reboots/claim", a.requireAgent(a.agentNodeRebootClaim))
	mux.HandleFunc("POST /api/v1/agent/node-reboots/result", a.requireAgent(a.agentNodeRebootResult))
}

func (a *application) requestNodeReboot(w http.ResponseWriter, r *http.Request) {
	if principal, ok := store.AdminPrincipal(r.Context()); ok && principal.Account.Role != "owner" {
		writeError(w, http.StatusForbidden, "owner role required")
		return
	}
	nodeID := r.PathValue("id")
	if !accessPlanUUID.MatchString(nodeID) {
		writeError(w, http.StatusBadRequest, "invalid node identity")
		return
	}
	var input struct {
		ConfirmName   string `json:"confirm_name"`
		ConfirmReboot bool   `json:"confirm_reboot"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if readErr != nil || botbridge.DecodeRequest(raw, &input, "confirm_name", "confirm_reboot") != nil || !input.ConfirmReboot || strings.TrimSpace(input.ConfirmName) == "" || len(input.ConfirmName) > 80 {
		writeError(w, http.StatusBadRequest, "exact server name and reboot confirmation are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	job, err := a.store.QueueNodeReboot(ctx, nodeID, input.ConfirmName)
	switch {
	case errors.Is(err, store.ErrAdminPermission):
		writeError(w, http.StatusForbidden, "owner role required")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "node not found")
	case errors.Is(err, store.ErrNodeNameConflict):
		writeError(w, http.StatusConflict, "server name changed or confirmation does not match")
	case errors.Is(err, store.ErrNodeRebootNotReady):
		writeError(w, http.StatusConflict, "server must be online, healthy and synchronized before reboot")
	case errors.Is(err, store.ErrNodeRebootAgentRequired):
		writeError(w, http.StatusConflict, "update the node agent before using reboot")
	case errors.Is(err, store.ErrNodeRebootActive):
		writeError(w, http.StatusConflict, "server has an active operation or reboot request")
	case errors.Is(err, store.ErrNodeRebootCooldown):
		writeError(w, http.StatusConflict, "server was rebooted recently; wait before retrying")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "server reboot could not be queued")
	default:
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job, "queued": true, "delay_seconds": 20})
	}
}

func (a *application) agentNodeRebootClaim(w http.ResponseWriter, r *http.Request) {
	var input model.NodeRebootJobClaimRequest
	if err := readJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid reboot claim request")
		return
	}
	input.OwnerInstanceID = strings.TrimSpace(input.OwnerInstanceID)
	if !validUUIDString(input.OwnerInstanceID) {
		writeError(w, http.StatusBadRequest, "invalid owner_instance_id")
		return
	}
	node := currentNode(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	grant, err := a.store.ClaimNodeRebootJob(ctx, node.ID, input.OwnerInstanceID)
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reboot request unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, grant)
}

func (a *application) agentNodeRebootResult(w http.ResponseWriter, r *http.Request) {
	var input model.NodeRebootJobResult
	if err := readJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid reboot result")
		return
	}
	input.JobID = strings.TrimSpace(input.JobID)
	input.OwnerInstanceID = strings.TrimSpace(input.OwnerInstanceID)
	input.Status = strings.TrimSpace(input.Status)
	input.FailureCode = strings.TrimSpace(input.FailureCode)
	if !validUUIDString(input.JobID) || !validUUIDString(input.OwnerInstanceID) {
		writeError(w, http.StatusBadRequest, "invalid reboot job identity")
		return
	}
	node := currentNode(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.store.ReportNodeRebootJob(ctx, node.ID, input); err != nil {
		switch {
		case errors.Is(err, store.ErrNodeRebootJobNotFound):
			writeError(w, http.StatusConflict, "reboot job is no longer active")
		case errors.Is(err, store.ErrNodeRebootResultInvalid):
			writeError(w, http.StatusBadRequest, "invalid reboot result state")
		default:
			writeError(w, http.StatusInternalServerError, "reboot result could not be recorded")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
