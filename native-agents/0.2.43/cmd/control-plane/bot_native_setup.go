package main

import (
	"errors"
	"net/http"
	"vpn-platform/internal/store"
)

func (a *application) configureNativeBot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminOwnerRequired(w, r) {
		return
	}
	var body struct {
		SubscriptionBase string `json:"subscription_base"`
		AccessPlanID     string `json:"access_plan_id"`
	}
	if !accessPlanUUID.MatchString(r.PathValue("id")) || tenantReadJSON(w, r, &body) != nil {
		writeError(w, 400, "invalid native bot configuration")
		return
	}
	out, err := a.store.ConfigureNativeBot(r.Context(), r.PathValue("id"), body.SubscriptionBase, body.AccessPlanID)
	switch {
	case errors.Is(err, store.ErrBotBridgeConflict):
		writeError(w, 409, "bot profile already configured or imported")
	case errors.Is(err, store.ErrBotBridgeRequest):
		writeError(w, 400, "invalid native bot configuration")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "tenant or access plan unavailable")
	case err != nil:
		writeError(w, 503, "bot configuration unavailable")
	default:
		writeJSON(w, 200, out)
	}
}
