package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

const (
	executionLeaseTTL = 60 * time.Second

	executionLeaseRenewAfterSeconds int64 = 15
)

func validUUIDString(
	value string,
) bool {
	value = strings.TrimSpace(value)

	if len(value) != 36 {
		return false
	}

	for i := 0; i < len(value); i++ {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' {
				return false
			}

		default:
			c := value[i]

			isHex :=
				(c >= '0' && c <= '9') ||
					(c >= 'a' && c <= 'f') ||
					(c >= 'A' && c <= 'F')

			if !isHex {
				return false
			}
		}
	}

	return true
}

func validateExecutionAssignmentInput(
	execution model.ExecutionAssignment,
) bool {
	return execution.Generation >= 1 &&
		execution.ExecutionEpoch >= 1 &&
		validUUIDString(execution.DeploymentID) &&
		validUUIDString(execution.ExecutionID)
}

func writeExecutionLeaseError(
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
			"execution deployment not found",
		)

	case errors.Is(
		err,
		store.ErrExecutionIdentityMismatch,
	):
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)

	case errors.Is(
		err,
		store.ErrExecutionLeaseNotClaimable,
	),
		errors.Is(
			err,
			store.ErrExecutionLeaseConflict,
		),
		errors.Is(
			err,
			store.ErrExecutionLeaseExpired,
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

func (a *application) agentExecutionClaim(
	w http.ResponseWriter,
	r *http.Request,
) {
	node := currentNode(r.Context())

	var input model.ExecutionLeaseClaimRequest

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

	leaseToken, err :=
		security.NewToken(48)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to generate execution lease",
		)
		return
	}

	leaseExpiresAt, err :=
		a.store.ClaimExecutionLease(
			r.Context(),
			node.ID,
			input.Execution,
			input.OwnerInstanceID,
			security.HashToken(
				leaseToken,
			),
			executionLeaseTTL,
		)

	if err != nil {
		writeExecutionLeaseError(
			w,
			err,
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
		model.ExecutionLeaseGrant{
			LeaseToken: leaseToken,

			LeaseExpiresAt: leaseExpiresAt,

			RenewAfterSeconds: executionLeaseRenewAfterSeconds,
		},
	)
}

func (a *application) agentExecutionRenew(
	w http.ResponseWriter,
	r *http.Request,
) {
	node := currentNode(r.Context())

	var input model.ExecutionLeaseRenewRequest

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

	if strings.TrimSpace(
		input.LeaseToken,
	) == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"lease_token required",
		)
		return
	}

	leaseExpiresAt, err :=
		a.store.RenewExecutionLease(
			r.Context(),
			node.ID,
			input.Execution,
			input.OwnerInstanceID,
			security.HashToken(
				input.LeaseToken,
			),
			executionLeaseTTL,
		)

	if err != nil {
		writeExecutionLeaseError(
			w,
			err,
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
		model.ExecutionLeaseGrant{
			LeaseExpiresAt: leaseExpiresAt,

			RenewAfterSeconds: executionLeaseRenewAfterSeconds,
		},
	)
}
