package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

type createExecutionFenceInput struct {
	Reason string `json:"reason"`
}

func (a *application) createExecutionFenceRequest(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if !validUUIDString(
		nodeID,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid node id",
		)
		return
	}

	generationRaw :=
		strings.TrimSpace(
			r.PathValue(
				"generation",
			),
		)

	generation, err :=
		strconv.ParseInt(
			generationRaw,
			10,
			64,
		)

	if err != nil ||
		generation < 1 {

		writeError(
			w,
			http.StatusBadRequest,
			"valid generation is required",
		)
		return
	}

	var input createExecutionFenceInput

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

	input.Reason =
		strings.TrimSpace(
			input.Reason,
		)

	if input.Reason == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"reason is required",
		)
		return
	}

	request, err :=
		a.store.CreateExecutionFenceRequestForGeneration(
			r.Context(),
			nodeID,
			generation,
			input.Reason,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"deployment not found",
		)
		return

	case errors.Is(
		err,
		store.ErrExecutionFenceNotRequestable,
	),
		errors.Is(
			err,
			store.ErrExecutionFenceConflict,
		),
		errors.Is(
			err,
			store.ErrExecutionLeaseConflict,
		):

		writeError(
			w,
			http.StatusConflict,
			err.Error(),
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
		request,
	)
}

func (a *application) agentExecutionFenceAck(
	w http.ResponseWriter,
	r *http.Request,
) {
	node :=
		currentNode(
			r.Context(),
		)

	var input model.ExecutionFenceAckRequest

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

	if !validUUIDString(
		input.FenceRequestID,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid fence_request_id",
		)
		return
	}

	if !validateExecutionAssignmentInput(
		input.Execution,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid execution identity",
		)
		return
	}

	if !validUUIDString(
		input.OwnerInstanceID,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid owner_instance_id",
		)
		return
	}

	rawProof :=
		strings.TrimSpace(
			input.FenceProofToken,
		)

	if rawProof == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"fence_proof_token required",
		)
		return
	}

	// Raw proof must stop at the HTTP boundary.
	// Store receives only its cryptographic hash.
	proofHash :=
		security.HashToken(
			rawProof,
		)

	request, err :=
		a.store.AcknowledgeExecutionFenceRequest(
			r.Context(),
			node.ID,
			input.FenceRequestID,
			input.Execution,
			input.OwnerInstanceID,
			proofHash,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"execution fence request not found",
		)
		return

	case errors.Is(
		err,
		store.ErrExecutionIdentityMismatch,
	),
		errors.Is(
			err,
			store.ErrExecutionFenceConflict,
		),
		errors.Is(
			err,
			store.ErrExecutionFenceProofInvalid,
		):

		// Deliberately generic: do not expose which proof
		// component failed.
		writeError(
			w,
			http.StatusConflict,
			"execution fence acknowledgement rejected",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			"execution fence acknowledgement failed",
		)
		return
	}

	w.Header().Set(
		"Cache-Control",
		"no-store",
	)

	writeJSON(
		w,
		http.StatusOK,
		request,
	)
}
