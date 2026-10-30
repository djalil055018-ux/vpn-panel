package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"vpn-platform/internal/store"
)

func recoveryGeneration(
	r *http.Request,
) (int64, error) {
	raw :=
		strings.TrimSpace(
			r.PathValue("generation"),
		)

	value, err :=
		strconv.ParseInt(
			raw,
			10,
			64,
		)

	if err != nil ||
		value < 1 {

		return 0,
			errors.New(
				"valid generation is required",
			)
	}

	return value, nil
}

func writeRecoveryAttemptError(
	w http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			err.Error(),
		)

	case errors.Is(
		err,
		store.ErrRecoveryAttemptBlocked,
	),
		errors.Is(
			err,
			store.ErrRecoveryAttemptAlreadyApproved,
		),
		errors.Is(
			err,
			store.ErrRecoveryAttemptNotApprovable,
		),
		errors.Is(
			err,
			store.ErrRecoveryAttemptNotExecutable,
		),
		errors.Is(
			err,
			store.ErrRecoveryAttemptTerminal,
		),
		errors.Is(
			err,
			store.ErrRecoveryAttemptStale,
		),
		errors.Is(
			err,
			store.ErrRecoveryAttemptConflict,
		):

		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)

	default:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
	}
}

func (a *application) createRecoveryAttempt(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	generation, err :=
		recoveryGeneration(r)

	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	plan, err :=
		a.store.CreateRecoveryAttempt(
			r.Context(),
			nodeID,
			generation,
		)

	if err != nil {
		writeRecoveryAttemptError(
			w,
			err,
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		map[string]any{
			"recovery_attempt": plan,
		},
	)
}

func (a *application) getRecoveryAttempt(
	w http.ResponseWriter,
	r *http.Request,
) {
	id :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, err :=
		a.store.GetRecoveryAttempt(
			r.Context(),
			id,
		)

	if err != nil {
		writeRecoveryAttemptError(
			w,
			err,
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"recovery_attempt": plan,
		},
	)
}

func (a *application) approveRecoveryAttempt(
	w http.ResponseWriter,
	r *http.Request,
) {
	id :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, err :=
		a.store.ApproveRecoveryAttempt(
			r.Context(),
			id,
		)

	if err != nil {
		writeRecoveryAttemptError(
			w,
			err,
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"recovery_attempt": plan,
		},
	)
}

func (a *application) cancelRecoveryAttempt(
	w http.ResponseWriter,
	r *http.Request,
) {
	id :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, changed, err :=
		a.store.CancelRecoveryAttempt(
			r.Context(),
			id,
		)

	if err != nil {
		writeRecoveryAttemptError(
			w,
			err,
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"recovery_attempt": plan,
			"changed":          changed,
		},
	)
}

func (a *application) executeRecoveryAttempt(
	w http.ResponseWriter,
	r *http.Request,
) {
	id :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, changed, err :=
		a.store.ExecuteRecoveryAttempt(
			r.Context(),
			id,
		)

	if err != nil {
		writeRecoveryAttemptError(
			w,
			err,
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"recovery_attempt": plan,
			"changed":          changed,
		},
	)
}
