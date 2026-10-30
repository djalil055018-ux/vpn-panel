package main

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

const (
	certificateJobLeaseTTL = 15 * time.Minute

	certificateJobRenewAfterSeconds = int64(300)
)

func validCertificateFingerprint(
	value string,
) bool {
	value =
		strings.ToLower(
			strings.ReplaceAll(
				strings.TrimSpace(value),
				":",
				"",
			),
		)

	raw, err :=
		hex.DecodeString(value)

	return err == nil &&
		len(raw) == 32
}

func (a *application) queueCertificateOperation(
	w http.ResponseWriter,
	r *http.Request,
	operation string,
) {
	certificateID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	job, err :=
		a.store.QueueCertificateJob(
			r.Context(),
			certificateID,
			operation,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"certificate not found",
		)
		return

	case errors.Is(
		err,
		store.ErrCertificateJobExists,
	):
		writeError(
			w,
			http.StatusConflict,
			"active certificate job already exists",
		)
		return

	case errors.Is(
		err,
		store.ErrCertificateJobInvalidState,
	):
		writeError(
			w,
			http.StatusConflict,
			"certificate is not in a valid state for this operation",
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
		http.StatusAccepted,
		job,
	)
}

func (a *application) issueCertificate(
	w http.ResponseWriter,
	r *http.Request,
) {
	a.queueCertificateOperation(
		w,
		r,
		"issue",
	)
}

func (a *application) renewCertificate(
	w http.ResponseWriter,
	r *http.Request,
) {
	a.queueCertificateOperation(
		w,
		r,
		"renew",
	)
}

func (a *application) agentCertificateJobClaim(
	w http.ResponseWriter,
	r *http.Request,
) {
	node :=
		currentNode(
			r.Context(),
		)

	var input model.CertificateJobClaimRequest

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

	input.OwnerInstanceID =
		strings.TrimSpace(
			input.OwnerInstanceID,
		)

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
			"failed to generate certificate lease",
		)
		return
	}

	work, err :=
		a.store.ClaimCertificateJob(
			r.Context(),
			node.ID,
			input.OwnerInstanceID,
			security.HashToken(
				leaseToken,
			),
			certificateJobLeaseTTL,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		w.WriteHeader(
			http.StatusNoContent,
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

	w.Header().Set(
		"Cache-Control",
		"no-store",
	)

	writeJSON(
		w,
		http.StatusOK,
		model.CertificateJobGrant{
			JobID:             work.JobID,
			CertificateID:     work.CertificateID,
			Operation:         work.Operation,
			Domain:            work.Domain,
			Provider:          work.Provider,
			ChallengeType:     work.ChallengeType,
			Environment:       work.Environment,
			ContactEmail:      work.ContactEmail,
			CertificateRef:    work.CertificateRef,
			LeaseToken:        leaseToken,
			LeaseExpiresAt:    work.LeaseExpiresAt,
			RenewAfterSeconds: certificateJobRenewAfterSeconds,
		},
	)
}

func (a *application) agentCertificateJobRenew(
	w http.ResponseWriter,
	r *http.Request,
) {
	node :=
		currentNode(
			r.Context(),
		)

	var input model.CertificateJobLeaseRenewRequest

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

	input.JobID =
		strings.TrimSpace(
			input.JobID,
		)

	input.OwnerInstanceID =
		strings.TrimSpace(
			input.OwnerInstanceID,
		)

	input.LeaseToken =
		strings.TrimSpace(
			input.LeaseToken,
		)

	if !validUUIDString(
		input.JobID,
	) ||
		!validUUIDString(
			input.OwnerInstanceID,
		) ||
		input.LeaseToken == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid certificate lease renewal request",
		)
		return
	}

	expiresAt, err :=
		a.store.RenewCertificateJobLease(
			r.Context(),
			node.ID,
			input.JobID,
			input.OwnerInstanceID,
			security.HashToken(
				input.LeaseToken,
			),
			certificateJobLeaseTTL,
		)

	if errors.Is(
		err,
		store.ErrCertificateJobLeaseConflict,
	) {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
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

	w.Header().Set(
		"Cache-Control",
		"no-store",
	)

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"lease_expires_at":    expiresAt,
			"renew_after_seconds": certificateJobRenewAfterSeconds,
		},
	)
}

func (a *application) agentCertificateJobResult(
	w http.ResponseWriter,
	r *http.Request,
) {
	node :=
		currentNode(
			r.Context(),
		)

	var report model.CertificateJobResult

	if err :=
		readJSON(
			r,
			&report,
		); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	report.JobID =
		strings.TrimSpace(
			report.JobID,
		)

	report.CertificateID =
		strings.TrimSpace(
			report.CertificateID,
		)

	report.LeaseToken =
		strings.TrimSpace(
			report.LeaseToken,
		)

	report.Issuer =
		strings.TrimSpace(
			report.Issuer,
		)

	report.FingerprintSHA256 =
		strings.ToLower(
			strings.ReplaceAll(
				strings.TrimSpace(
					report.FingerprintSHA256,
				),
				":",
				"",
			),
		)

	report.ErrorMessage =
		strings.TrimSpace(
			report.ErrorMessage,
		)

	if !validUUIDString(
		report.JobID,
	) ||
		!validUUIDString(
			report.CertificateID,
		) ||
		report.LeaseToken == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid certificate result identity",
		)
		return
	}

	if report.Success {
		metadataEmpty := report.Issuer == "" && report.FingerprintSHA256 == "" && report.NotBefore == nil && report.NotAfter == nil
		metadataValid := report.Issuer != "" && validCertificateFingerprint(report.FingerprintSHA256) && report.NotBefore != nil && report.NotAfter != nil && report.NotAfter.After(*report.NotBefore)
		if !metadataEmpty && !metadataValid {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid successful certificate result",
			)
			return
		}
	} else if report.ErrorMessage == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"error_message is required for failed certificate result",
		)
		return
	}

	err :=
		a.store.CompleteCertificateJob(
			r.Context(),
			node.ID,
			report,
			security.HashToken(
				report.LeaseToken,
			),
		)

	switch {
	case errors.Is(
		err,
		store.ErrCertificateJobLeaseConflict,
	):
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return

	case errors.Is(err, store.ErrCertificateResultInvalid):
		writeError(w, http.StatusBadRequest, "certificate result does not match the claimed operation")
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}
