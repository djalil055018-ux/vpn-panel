package main

import (
	"context"
	"net/http"
	"time"
)

func (a *application) customerSubscriptionState(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := a.store.CustomerSubscriptionState(ctx, r.PathValue("client_id"))
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
