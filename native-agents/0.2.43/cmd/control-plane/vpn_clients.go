package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/store"
)

func parseVPNClientExpiry(
	raw *string,
) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}

	value := strings.TrimSpace(*raw)

	if value == "" {
		return nil, errors.New(
			"expires_at must be RFC3339",
		)
	}

	parsed, err := time.Parse(
		time.RFC3339,
		value,
	)

	if err != nil {
		return nil, errors.New(
			"expires_at must be RFC3339",
		)
	}

	parsed = parsed.UTC()

	return &parsed, nil
}

func (a *application) createVPNClient(
	w http.ResponseWriter,
	r *http.Request,
) {
	tenantID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if tenantID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"tenant id is required",
		)
		return
	}

	var input struct {
		Name      string  `json:"name"`
		ExpiresAt *string `json:"expires_at"`
	}

	if err := readJSON(
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

	input.Name = strings.TrimSpace(
		input.Name,
	)

	if input.Name == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"name is required",
		)
		return
	}

	expiresAt, err :=
		parseVPNClientExpiry(
			input.ExpiresAt,
		)

	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	client, err :=
		a.store.CreateVPNClient(
			r.Context(),
			tenantID,
			input.Name,
			expiresAt,
		)

	switch {
	case errors.Is(err, store.ErrTenantQuota):
		writeError(w, 409, "tenant client limit reached")
		return
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"tenant not found",
		)
		return

	case errors.Is(err, store.ErrRemnawaveHold):
		writeError(w, http.StatusConflict, err.Error())
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
		client,
	)
}

func (a *application) listVPNClients(
	w http.ResponseWriter,
	r *http.Request,
) {
	tenantID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if tenantID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"tenant id is required",
		)
		return
	}

	clients, err :=
		a.store.ListVPNClients(
			r.Context(),
			tenantID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"tenant not found",
		)
		return

	case errors.Is(err, store.ErrRemnawaveHold):
		writeError(w, http.StatusConflict, err.Error())
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
		map[string]any{
			"clients": clients,
		},
	)
}

func (a *application) getVPNClient(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if clientID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"client id is required",
		)
		return
	}

	client, err :=
		a.store.GetVPNClient(
			r.Context(),
			clientID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn client not found",
		)
		return

	case errors.Is(err, store.ErrRemnawaveHold):
		writeError(w, http.StatusConflict, err.Error())
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
		client,
	)
}

func (a *application) updateVPNClient(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if clientID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"client id is required",
		)
		return
	}

	var input struct {
		Name           *string `json:"name"`
		Status         *string `json:"status"`
		ExpiresAt      *string `json:"expires_at"`
		ClearExpiresAt bool    `json:"clear_expires_at"`
	}

	if err := readJSON(
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

	if input.Name == nil &&
		input.Status == nil &&
		input.ExpiresAt == nil &&
		!input.ClearExpiresAt {

		writeError(
			w,
			http.StatusBadRequest,
			"at least one field is required",
		)
		return
	}

	if input.ExpiresAt != nil &&
		input.ClearExpiresAt {

		writeError(
			w,
			http.StatusBadRequest,
			"expires_at and clear_expires_at cannot be used together",
		)
		return
	}

	if input.Name != nil {
		value := strings.TrimSpace(
			*input.Name,
		)

		if value == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"name cannot be empty",
			)
			return
		}

		input.Name = &value
	}

	if input.Status != nil {
		value := strings.TrimSpace(
			*input.Status,
		)

		if value != "active" &&
			value != "disabled" {

			writeError(
				w,
				http.StatusBadRequest,
				"status must be active or disabled",
			)
			return
		}

		input.Status = &value
	}

	var expiresAt *time.Time
	setExpiresAt := false

	if input.ExpiresAt != nil {
		parsed, err :=
			parseVPNClientExpiry(
				input.ExpiresAt,
			)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				err.Error(),
			)
			return
		}

		expiresAt = parsed
		setExpiresAt = true
	}

	if input.ClearExpiresAt {
		expiresAt = nil
		setExpiresAt = true
	}

	client, err :=
		a.store.UpdateVPNClient(
			r.Context(),
			clientID,
			input.Name,
			input.Status,
			expiresAt,
			setExpiresAt,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn client not found",
		)
		return

	case errors.Is(err, store.ErrRemnawaveHold):
		writeError(w, http.StatusConflict, err.Error())
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
		client,
	)
}

func (a *application) setVPNClientEnabled(
	w http.ResponseWriter,
	r *http.Request,
	status string,
) {
	clientID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if clientID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"client id is required",
		)
		return
	}

	client, err :=
		a.store.SetVPNClientStatus(
			r.Context(),
			clientID,
			status,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn client not found",
		)
		return

	case errors.Is(err, store.ErrRemnawaveHold):
		writeError(w, http.StatusConflict, err.Error())
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
		client,
	)
}

func (a *application) disableVPNClient(
	w http.ResponseWriter,
	r *http.Request,
) {
	a.setVPNClientEnabled(
		w,
		r,
		"disabled",
	)
}

func (a *application) enableVPNClient(
	w http.ResponseWriter,
	r *http.Request,
) {
	a.setVPNClientEnabled(
		w,
		r,
		"active",
	)
}
