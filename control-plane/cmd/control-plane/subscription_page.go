package main

import (
	"context"
	"errors"
	"net/http"
	"time"
	"vpn-platform/internal/store"
)

func (a *application) getPublicSubscriptionInfo(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	token := r.PathValue("token")
	if !publicImportedAlias.MatchString(token) {
		http.NotFound(w, r)
		return
	}
	proof := store.SubscriptionDeviceProof{Alias: token}
	if len(token) == 75 {
		key, err := subscriptionSigningKey()
		if err != nil {
			writeError(w, 503, "subscription service unavailable")
			return
		}
		if id, version, hash, err := parseSubscriptionToken(key, token); err == nil {
			proof = store.SubscriptionDeviceProof{TokenID: id, TokenVersion: version, TokenHash: hash}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	info, err := a.store.PublicSubscriptionInfo(ctx, proof)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, 503, "subscription information unavailable")
		return
	}
	writeJSON(w, 200, info)
}
