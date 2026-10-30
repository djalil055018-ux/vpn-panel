package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"os"
	"strings"
	"vpn-platform/internal/subscriptioncompat"

	"vpn-platform/internal/store"
)

const subscriptionTokenIDSize = 16
const subscriptionTokenPayloadSize = 24
const subscriptionTokenRawSize = 56

func subscriptionSigningKey() ([]byte, error) {
	value := strings.TrimSpace(
		os.Getenv("SUBSCRIPTION_SIGNING_KEY"),
	)

	if value == "" {
		return nil,
			errors.New(
				"subscription signing key is not configured",
			)
	}

	key, err :=
		base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil,
			errors.New(
				"subscription signing key must be 32 bytes",
			)
	}

	return key, nil
}

func newSubscriptionTokenID() ([]byte, error) {
	value := make(
		[]byte,
		subscriptionTokenIDSize,
	)

	if _, err := rand.Read(value); err != nil {
		return nil, err
	}

	return value, nil
}

func buildSubscriptionToken(
	key []byte,
	tokenID []byte,
	version int64,
) (
	string,
	[]byte,
	error,
) {
	if len(tokenID) != subscriptionTokenIDSize ||
		version < 1 {
		return "", nil,
			errors.New(
				"invalid subscription token material",
			)
	}

	payload := make(
		[]byte,
		subscriptionTokenPayloadSize,
	)

	copy(
		payload[:subscriptionTokenIDSize],
		tokenID,
	)

	binary.BigEndian.PutUint64(
		payload[subscriptionTokenIDSize:],
		uint64(version),
	)

	mac := hmac.New(
		sha256.New,
		key,
	)

	_, _ = mac.Write(payload)

	raw := make(
		[]byte,
		0,
		subscriptionTokenRawSize,
	)

	raw = append(raw, payload...)
	raw = append(raw, mac.Sum(nil)...)

	sum := sha256.Sum256(raw)

	token :=
		base64.RawURLEncoding.EncodeToString(raw)

	return token, sum[:], nil
}

func parseSubscriptionToken(
	key []byte,
	token string,
) (
	[]byte,
	int64,
	[]byte,
	error,
) {
	raw, err :=
		base64.RawURLEncoding.DecodeString(
			strings.TrimSpace(token),
		)
	if err != nil ||
		len(raw) != subscriptionTokenRawSize {
		return nil, 0, nil,
			errors.New(
				"invalid subscription token",
			)
	}

	payload :=
		raw[:subscriptionTokenPayloadSize]

	signature :=
		raw[subscriptionTokenPayloadSize:]

	mac := hmac.New(
		sha256.New,
		key,
	)

	_, _ = mac.Write(payload)

	if !hmac.Equal(
		signature,
		mac.Sum(nil),
	) {
		return nil, 0, nil,
			errors.New(
				"invalid subscription token",
			)
	}

	tokenID := make(
		[]byte,
		subscriptionTokenIDSize,
	)

	copy(
		tokenID,
		payload[:subscriptionTokenIDSize],
	)

	version :=
		int64(
			binary.BigEndian.Uint64(
				payload[subscriptionTokenIDSize:],
			),
		)

	if version < 1 {
		return nil, 0, nil,
			errors.New(
				"invalid subscription token",
			)
	}

	sum := sha256.Sum256(raw)

	return tokenID, version, sum[:], nil
}

func subscriptionTokenPrefix(
	token string,
) string {
	if len(token) <= 10 {
		return token
	}

	return token[:10]
}

func subscriptionPath(
	token string,
) string {
	return "/sub/" + token
}

func subscriptionResponse(
	subscription store.VPNClientSubscription,
	token string,
) map[string]any {
	return map[string]any{
		"id":             subscription.ID,
		"client_id":      subscription.ClientID,
		"status":         subscription.Status,
		"token_version":  subscription.TokenVersion,
		"token_prefix":   subscription.TokenPrefix,
		"created_at":     subscription.CreatedAt,
		"rotated_at":     subscription.RotatedAt,
		"last_access_at": subscription.LastAccessAt,
		"path":           subscriptionPath(token),
	}
}

func (a *application) createVPNClientSubscription(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	key, err := subscriptionSigningKey()
	if err != nil {
		writeError(
			w,
			http.StatusServiceUnavailable,
			err.Error(),
		)
		return
	}

	tokenID, err :=
		newSubscriptionTokenID()
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	const version int64 = 1

	token, tokenHash, err :=
		buildSubscriptionToken(
			key,
			tokenID,
			version,
		)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	subscription, err :=
		a.store.CreateVPNClientSubscription(
			r.Context(),
			clientID,
			tokenID,
			version,
			tokenHash,
			subscriptionTokenPrefix(token),
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"active vpn client not found",
		)
		return

	case errors.Is(
		err,
		store.ErrVPNClientSubscriptionExists,
	):
		writeError(
			w,
			http.StatusConflict,
			"active subscription already exists",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		subscriptionResponse(
			subscription,
			token,
		),
	)
}

func (a *application) getVPNClientSubscription(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	key, err := subscriptionSigningKey()
	if err != nil {
		writeError(
			w,
			http.StatusServiceUnavailable,
			err.Error(),
		)
		return
	}

	subscription, err :=
		a.store.GetVPNClientSubscription(
			r.Context(),
			clientID,
		)

	if errors.Is(err, store.ErrNotFound) {
		writeError(
			w,
			http.StatusNotFound,
			"active subscription not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	token, tokenHash, err :=
		buildSubscriptionToken(
			key,
			subscription.TokenID,
			subscription.TokenVersion,
		)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	if !hmac.Equal(
		tokenHash,
		subscription.TokenHash,
	) {
		writeError(
			w,
			http.StatusServiceUnavailable,
			"subscription signing key mismatch",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		subscriptionResponse(
			subscription,
			token,
		),
	)
}

func (a *application) rotateVPNClientSubscription(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	key, err := subscriptionSigningKey()
	if err != nil {
		writeError(
			w,
			http.StatusServiceUnavailable,
			err.Error(),
		)
		return
	}

	current, err :=
		a.store.GetVPNClientSubscription(
			r.Context(),
			clientID,
		)

	if errors.Is(err, store.ErrNotFound) {
		writeError(
			w,
			http.StatusNotFound,
			"active subscription not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	newVersion :=
		current.TokenVersion + 1

	token, tokenHash, err :=
		buildSubscriptionToken(
			key,
			current.TokenID,
			newVersion,
		)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	subscription, err :=
		a.store.RotateVPNClientSubscription(
			r.Context(),
			clientID,
			current.TokenVersion,
			newVersion,
			tokenHash,
			subscriptionTokenPrefix(token),
		)

	if errors.Is(
		err,
		store.ErrVPNClientSubscriptionConflict,
	) {
		writeError(
			w,
			http.StatusConflict,
			"subscription changed concurrently",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		subscriptionResponse(
			subscription,
			token,
		),
	)
}

func (a *application) getPublicVPNSubscription(
	w http.ResponseWriter,
	r *http.Request,
) {
	privateSubscriptionHeaders(w)
	token :=
		strings.TrimSpace(
			r.PathValue("token"),
		)
	// Existing bot aliases retain the same device registry and revocation checks
	// on the canonical PAUK URL. No new credential or subscription is created.
	if len(token) != 75 && publicImportedAlias.MatchString(token) {
		r.SetPathValue("alias", token)
		a.getImportedSubscription(w, r)
		return
	}

	key, err := subscriptionSigningKey()
	if err != nil {
		writeError(
			w,
			http.StatusServiceUnavailable,
			"subscription service unavailable",
		)
		return
	}

	tokenID, tokenVersion, tokenHash, err :=
		parseSubscriptionToken(
			key,
			token,
		)
	if err != nil {
		if publicImportedAlias.MatchString(token) {
			r.SetPathValue("alias", token)
			a.getImportedSubscription(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	clientID, err :=
		a.store.ResolveVPNClientSubscription(
			r.Context(),
			tokenID,
			tokenVersion,
			tokenHash,
		)

	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"subscription resolution failed",
		)
		return
	}

	r = r.WithContext(context.WithValue(r.Context(), subscriptionDeviceProofKey{}, store.SubscriptionDeviceProof{TokenID: tokenID, TokenHash: tokenHash, TokenVersion: tokenVersion}))
	imported, importedErr := a.store.ReadImportedSubscription(r.Context(), store.ImportedSubscriptionLookup{NativeClientID: clientID})
	if !errors.Is(importedErr, store.ErrSubscriptionNotImported) {
		if importedSubscriptionError(w, r, importedErr) {
			return
		}
		// Explicit native file downloads retain their own effective grant checks.
		if format := r.URL.Query().Get("format"); format != "wireguard" && format != "amneziawg" && format != "openvpn" {
			a.serveImportedSubscription(w, r, imported)
			return
		}
	}

	a.serveNativeVPNSubscription(w, r, clientID, "")
}

func (a *application) serveNativeVPNSubscription(w http.ResponseWriter, r *http.Request, clientID, alias string) {
	connections, err :=
		a.store.ListVPNClientConnections(
			r.Context(),
			clientID,
		)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if format := r.URL.Query().Get("format"); format == "wireguard" || format == "amneziawg" || format == "openvpn" {
		for _, c := range connections {
			if c.Protocol == format && c.ServiceID == r.URL.Query().Get("service_id") && c.Config != "" {
				if _, ok := a.checkSubscriptionDevice(w, r, clientID, alias, false); !ok {
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("Content-Disposition", `attachment; filename="`+c.ConfigFilename+`"`)
				_, _ = w.Write([]byte(c.Config))
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	if _, ok := a.checkSubscriptionDevice(w, r, clientID, alias, false); !ok {
		return
	}
	client, err := a.store.GetVPNClient(r.Context(), clientID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	branding, err := a.store.GetTenantBranding(r.Context(), client.TenantID)
	if err != nil {
		writeError(w, 503, "subscription branding unavailable")
		return
	}
	setSubscriptionBranding(w.Header(), branding.DisplayName)
	subscriptioncompat.SetClientNetworkHeaders(w.Header(), r.UserAgent())
	if a.serveNativeAutoSubscription(w, r, client, connections) {
		return
	}
	lines := make(
		[]string,
		0,
		len(connections),
	)

	for _, connection := range connections {
		if connection.Protocol == "wireguard" || connection.Protocol == "amneziawg" || connection.Protocol == "openvpn" {
			continue
		}
		uri, err :=
			buildVPNConnectionURI(
				connection,
			)
		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"subscription rendering failed",
			)
			return
		}

		lines = append(
			lines,
			uri,
		)
	}

	payload :=
		strings.Join(lines, "\n")

	if payload != "" {
		payload += "\n"
	}

	encoded :=
		base64.StdEncoding.EncodeToString(
			[]byte(payload),
		)
	response, err := subscriptioncompat.AdaptHiddifySubscription([]byte(encoded), "XRAY_BASE64", r.UserAgent())
	if err != nil {
		writeError(w, 503, "subscription rendering unavailable")
		return
	}

	w.Header().Set(
		"Content-Type",
		"text/plain; charset=utf-8",
	)

	w.Header().Set(
		"Cache-Control",
		"no-store, no-cache, must-revalidate",
	)

	w.Header().Set(
		"Pragma",
		"no-cache",
	)

	w.Header().Set(
		"X-Content-Type-Options",
		"nosniff",
	)

	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(
		response,
	)
}
