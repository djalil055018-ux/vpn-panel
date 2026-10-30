package main

import (
	"errors"
	"net/http"
	"strings"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func (a *application) updateVPNServiceSubscriptionName(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if !accessPlanUUID.MatchString(id) {
		writeError(w, http.StatusBadRequest, "valid service id is required")
		return
	}
	var input struct {
		Name *string `json:"name"`
	}
	if err := readJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.Name == nil || !model.ValidSubscriptionName(*input.Name) {
		writeError(w, http.StatusBadRequest, "name must be one line of at most 200 characters; empty resets the name")
		return
	}
	service, err := a.store.SetVPNServiceSubscriptionName(r.Context(), id, *input.Name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "vpn service not found")
		return
	case errors.Is(err, store.ErrSubscriptionName):
		writeError(w, http.StatusBadRequest, "invalid subscription name")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save subscription name")
		return
	}
	writeJSON(w, http.StatusOK, service)
}
