package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"vpn-platform/internal/store"
)

func newRealityShortID() (
	string,
	error,
) {
	raw := make([]byte, 8)

	if _, err :=
		rand.Read(raw); err != nil {

		return "", err
	}

	return hex.EncodeToString(raw),
		nil
}

func (a *application) configureVPNServiceReality(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	var input struct {
		Destination string `json:"destination"`
		ServerName  string `json:"server_name"`
		Fingerprint string `json:"fingerprint"`
	}

	if err :=
		readJSON(
			r,
			&input,
		); err != nil {

		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.Destination =
		strings.TrimSpace(
			input.Destination,
		)

	input.ServerName =
		strings.TrimSpace(
			input.ServerName,
		)

	input.Fingerprint =
		strings.TrimSpace(
			input.Fingerprint,
		)

	if input.Destination == "" ||
		input.ServerName == "" {

		writeError(
			w,
			http.StatusBadRequest,
			"destination and server_name are required",
		)
		return
	}

	if input.Fingerprint == "" {
		input.Fingerprint = "chrome"
	}

	shortID, err :=
		newRealityShortID()

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	reality, err :=
		a.store.ConfigureVPNServiceReality(
			r.Context(),
			serviceID,
			input.Destination,
			input.ServerName,
			input.Fingerprint,
			shortID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"disabled VLESS TCP REALITY service not found",
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
		http.StatusOK,
		reality,
	)
}

func (a *application) updateVPNServiceReality(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID := strings.TrimSpace(
		r.PathValue("id"),
	)

	var input struct {
		Destination string `json:"destination"`
		ServerName  string `json:"server_name"`
		Fingerprint string `json:"fingerprint"`
	}

	if err := readJSON(r, &input); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.Destination =
		strings.TrimSpace(input.Destination)

	input.ServerName =
		strings.TrimSpace(input.ServerName)

	input.Fingerprint =
		strings.TrimSpace(input.Fingerprint)

	if input.Destination == "" ||
		input.ServerName == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"destination and server_name are required",
		)
		return
	}

	if input.Fingerprint == "" {
		input.Fingerprint = "chrome"
	}

	state, err :=
		a.store.UpdateVPNServiceRealityAndRebuild(
			r.Context(),
			serviceID,
			input.Destination,
			input.ServerName,
			input.Fingerprint,
		)

	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(
			w,
			http.StatusNotFound,
			"enabled VLESS TCP REALITY service not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"service_id": serviceID,
			"generation": state.Generation,
			"status":     "accepted",
		},
	)
}

func (a *application) getVPNServiceReality(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if serviceID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"vpn service id is required",
		)
		return
	}

	reality, err :=
		a.store.GetVPNServiceReality(
			r.Context(),
			serviceID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"reality configuration not found",
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

	// Do not expose node-local secret material here.
	// PublicKey is required by connection/subscription generation,
	// but the Protocol Manager does not need to return it.
	reality.PublicKey = nil

	writeJSON(
		w,
		http.StatusOK,
		reality,
	)
}

func (a *application) disableVPNService(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	state, err :=
		a.store.SetVPNServiceEnabledAndRebuild(
			r.Context(),
			serviceID,
			false,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn service not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"service_id": serviceID,
			"generation": state.Generation,
			"status":     "accepted",
		},
	)
}

func (a *application) enableVPNService(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	state, err :=
		a.store.SetVPNServiceEnabledAndRebuild(
			r.Context(),
			serviceID,
			true,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn service not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"service_id": serviceID,

			"generation": state.Generation,

			"status": "accepted",
		},
	)
}
