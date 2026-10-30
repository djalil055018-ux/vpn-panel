package main

import (
	"context"
	"net/http"
	"time"
	"vpn-platform/internal/store"
)

// Internal tenant-operator API. Neither an admin token nor a subscription link
// alone authorizes this route. The returned reference never leaves the trusted
// commerce backend; customer account authentication is a separate requirement.
func (a *application) customerSubscriptionContext(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	var input struct {
		Token string `json:"subscription_token"`
	}
	if botMutationBody(r, &input, "subscription_token") != nil || !publicImportedAlias.MatchString(input.Token) {
		writeError(w, 400, "valid subscription proof required")
		return
	}
	proof := store.SubscriptionDeviceProof{Alias: input.Token}
	if len(input.Token) == 75 {
		key, err := subscriptionSigningKey()
		if err != nil {
			writeError(w, 503, "subscription service unavailable")
			return
		}
		if id, version, hash, err := parseSubscriptionToken(key, input.Token); err == nil {
			proof = store.SubscriptionDeviceProof{TokenID: id, TokenVersion: version, TokenHash: hash}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := a.store.ResolveCustomerSubscription(ctx, proof)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (a *application) customerRenewNative(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	var input struct {
		ClientID string `json:"client_id"`
		Days     int    `json:"days"`
	}
	if botMutationBody(r, &input, "client_id", "days") != nil {
		botError(w, store.ErrBotBridgeRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := a.store.CustomerRenewNative(ctx, input.ClientID, input.Days, key)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}

func (a *application) customerNativeDevices(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	var input struct {
		Token    string `json:"subscription_token"`
		Action   string `json:"action"`
		DeviceID string `json:"device_id"`
	}
	if botMutationBody(r, &input, "subscription_token", "action", "device_id") != nil || len(input.Token) != 75 {
		botError(w, store.ErrBotBridgeRequest)
		return
	}
	signing, err := subscriptionSigningKey()
	if err != nil {
		writeError(w, 503, "subscription service unavailable")
		return
	}
	id, version, hash, err := parseSubscriptionToken(signing, input.Token)
	if err != nil {
		botError(w, store.ErrNotFound)
		return
	}
	proof := store.SubscriptionDeviceProof{TokenID: id, TokenVersion: version, TokenHash: hash}
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	var replacement string
	var replacementHash []byte
	if input.Action == "rotate" {
		replacement, replacementHash, err = buildSubscriptionToken(signing, id, version+1)
		if err != nil {
			writeError(w, 503, "subscription service unavailable")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := a.store.CustomerNativeDevices(ctx, proof, input.Action, input.DeviceID, key, replacement, replacementHash)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}

// The commerce service calls this only after verifying a payment. It can raise
// a native client's registered-device cap by exactly one slot, using a durable
// idempotency key. Bot-owned clients remain on the existing account workflow.
func (a *application) customerNativeDeviceLimit(w http.ResponseWriter, r *http.Request) {
	privateSubscriptionHeaders(w)
	key, err := botOperationKey(r)
	if err != nil {
		botError(w, err)
		return
	}
	var input struct {
		ClientID string `json:"client_id"`
		OldLimit int    `json:"old_limit"`
		NewLimit int    `json:"new_limit"`
	}
	if botMutationBody(r, &input, "client_id", "old_limit", "new_limit") != nil {
		botError(w, store.ErrBotBridgeRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := a.store.CustomerNativeDeviceLimit(ctx, input.ClientID, input.OldLimit, input.NewLimit, key)
	if err != nil {
		botError(w, err)
		return
	}
	writeJSON(w, out.Status, out.Body)
}
