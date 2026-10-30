package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

var (
	ErrCertificateJobExists = errors.New(
		"active certificate job already exists",
	)

	ErrCertificateJobInvalidState = errors.New(
		"certificate is not in a valid state for this operation",
	)

	ErrCertificateJobLeaseConflict = errors.New(
		"certificate job lease conflict",
	)

	ErrCertificateResultInvalid = errors.New(
		"certificate job result does not match its operation",
	)
)

type certificateJobScanner interface {
	Scan(dest ...any) error
}

func scanCertificateJob(
	row certificateJobScanner,
) (
	model.CertificateJob,
	error,
) {
	var result model.CertificateJob

	err := row.Scan(
		&result.ID,
		&result.TenantID,
		&result.NodeID,
		&result.CertificateID,
		&result.Operation,
		&result.Status,
		&result.OwnerInstanceID,
		&result.LeaseExpiresAt,
		&result.Attempt,
		&result.LastError,
		&result.CreatedAt,
		&result.ClaimedAt,
		&result.CompletedAt,
		&result.UpdatedAt,
	)

	return result, err
}

func (p *Postgres) QueueCertificateJob(
	ctx context.Context,
	certificateID string,
	operation string,
) (
	model.CertificateJob,
	error,
) {
	return p.queueCertificateJob(ctx, certificateID, operation, false)
}

func (p *Postgres) QueueCertificateDeletion(ctx context.Context, certificateID, confirmedDomain string) (model.CertificateJob, error) {
	if !adminOwnerAllowed(ctx) {
		return model.CertificateJob{}, ErrAdminPermission
	}
	if confirmedDomain == "" {
		return model.CertificateJob{}, ErrCertificateJobInvalidState
	}
	return p.queueCertificateJobConfirmed(ctx, certificateID, "delete", false, confirmedDomain)
}

func (p *Postgres) queueCertificateJob(ctx context.Context, certificateID, operation string, scheduled bool) (model.CertificateJob, error) {
	return p.queueCertificateJobConfirmed(ctx, certificateID, operation, scheduled, "")
}

func (p *Postgres) queueCertificateJobConfirmed(ctx context.Context, certificateID, operation string, scheduled bool, confirmedDomain string) (model.CertificateJob, error) {
	tx, err :=
		p.Pool.Begin(ctx)
	if err != nil {
		return model.CertificateJob{},
			err
	}

	defer tx.Rollback(ctx)

	var tenantID string
	var nodeID string
	var certificateStatus string
	var domain, agentVersion, nodeStatus string
	if operation == "delete" {
		err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM node_certificates WHERE id=$1::uuid`, certificateID).Scan(&tenantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return model.CertificateJob{}, ErrNotFound
		}
		if err != nil {
			return model.CertificateJob{}, err
		}
		if err = lockTenantAccess(ctx, tx, tenantID); err != nil {
			return model.CertificateJob{}, err
		}
	}

	err = tx.QueryRow(
		ctx,
		`
		SELECT c.tenant_id::text,c.node_id::text,c.status,c.domain,COALESCE(n.agent_version,''),n.status
		FROM node_certificates c JOIN nodes n ON n.id=c.node_id AND n.tenant_id=c.tenant_id
		WHERE c.id = $1::uuid
		FOR UPDATE OF c,n
		`,
		certificateID,
	).Scan(
		&tenantID,
		&nodeID,
		&certificateStatus,
		&domain,
		&agentVersion,
		&nodeStatus,
	)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.CertificateJob{},
			ErrNotFound
	}

	if err != nil {
		return model.CertificateJob{},
			err
	}
	if operation == "delete" {
		if confirmedDomain != domain || nodeStatus == "retired" || nodeStatus == "decommissioning" || !model.CertificateDeletionAgentCompatible(agentVersion) {
			return model.CertificateJob{}, ErrCertificateJobInvalidState
		}
		var inUse bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_service_tls WHERE certificate_id=$1::uuid) OR EXISTS(SELECT 1 FROM imported_tls_certificates WHERE certificate_id=$1::uuid)`, certificateID).Scan(&inUse); err != nil {
			return model.CertificateJob{}, err
		}
		if inUse {
			return model.CertificateJob{}, ErrCertificateInUse
		}
		if certificateStatus == "deleted" || certificateStatus == "deleting" {
			return model.CertificateJob{}, ErrCertificateJobInvalidState
		}
	} else {
		held, err := importedTLSRenewalHeld(ctx, tx, certificateID)
		if err != nil {
			return model.CertificateJob{}, err
		}
		if held {
			return model.CertificateJob{}, ErrCertificateJobInvalidState
		}
	}
	if scheduled {
		var due bool
		err = tx.QueryRow(ctx, `SELECT auto_renew AND status='active' AND not_after <= now()+interval '30 days'
			AND NOT EXISTS(SELECT 1 FROM certificate_jobs j WHERE j.certificate_id=c.id AND j.operation='renew' AND j.created_at>now()-interval '6 hours')
			FROM node_certificates c WHERE id=$1::uuid`, certificateID).Scan(&due)
		if err != nil {
			return model.CertificateJob{}, err
		}
		if !due {
			return model.CertificateJob{}, ErrCertificateJobInvalidState
		}
	}
	switch operation {
	case "issue":
		if certificateStatus != "draft" &&
			certificateStatus != "failed" {
			return model.CertificateJob{},
				ErrCertificateJobInvalidState
		}

	case "renew":
		if certificateStatus != "active" {
			return model.CertificateJob{},
				ErrCertificateJobInvalidState
		}

	case "delete":
		// Domain, agent version, dependency and node-state checks ran above.

	default:
		return model.CertificateJob{},
			fmt.Errorf(
				"unsupported certificate operation %q",
				operation,
			)
	}

	var activeExists bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM certificate_jobs
			WHERE certificate_id = $1::uuid
			  AND status IN (
				'pending',
				'claimed'
			  )
		)
		`,
		certificateID,
	).Scan(
		&activeExists,
	)

	if err != nil {
		return model.CertificateJob{},
			err
	}

	if activeExists {
		return model.CertificateJob{},
			ErrCertificateJobExists
	}

	row := tx.QueryRow(
		ctx,
		`
		INSERT INTO certificate_jobs(
			tenant_id,
			node_id,
			certificate_id,
			operation,
			status
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			$3::uuid,
			$4::text,
			'pending'
		)
		RETURNING
			id::text,
			tenant_id::text,
			node_id::text,
			certificate_id::text,
			operation,
			status,
			owner_instance_id::text,
			lease_expires_at,
			attempt,
			last_error,
			created_at,
			claimed_at,
			completed_at,
			updated_at
		`,
		tenantID,
		nodeID,
		certificateID,
		operation,
	)

	job, err :=
		scanCertificateJob(row)

	if err != nil {
		return model.CertificateJob{},
			err
	}

	nextCertificateStatus :=
		"pending"

	if operation == "renew" {
		nextCertificateStatus =
			"renewing"
	}
	if operation == "delete" {
		nextCertificateStatus = "deleting"
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE node_certificates
		SET
			status = $2::text,
			last_error = NULL,
			updated_at = now()
		WHERE id = $1::uuid
		`,
		certificateID,
		nextCertificateStatus,
	)

	if err != nil {
		return model.CertificateJob{},
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.CertificateJob{},
			err
	}

	return job, nil
}

func (p *Postgres) ClaimCertificateJob(
	ctx context.Context,
	nodeID string,
	ownerInstanceID string,
	leaseTokenHash string,
	ttl time.Duration,
) (
	model.CertificateJobWork,
	error,
) {
	tx, err :=
		p.Pool.Begin(ctx)
	if err != nil {
		return model.CertificateJobWork{},
			err
	}

	defer tx.Rollback(ctx)

	var work model.CertificateJobWork

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			j.id::text,
			j.certificate_id::text,
			j.operation,
			c.domain,
			c.provider,
			c.challenge_type,
			c.environment,
			c.contact_email,
			c.certificate_ref
		FROM certificate_jobs j
		JOIN node_certificates c
			ON c.id = j.certificate_id
			AND c.node_id = j.node_id
			AND c.tenant_id = j.tenant_id
		WHERE j.node_id = $1::uuid
		  AND (
			j.status = 'pending'
			OR (
				j.status = 'claimed'
				AND j.lease_expires_at <= now()
			)
		  )
		ORDER BY
			j.created_at ASC,
			j.id ASC
		FOR UPDATE OF j
		SKIP LOCKED
		LIMIT 1
		`,
		nodeID,
	).Scan(
		&work.JobID,
		&work.CertificateID,
		&work.Operation,
		&work.Domain,
		&work.Provider,
		&work.ChallengeType,
		&work.Environment,
		&work.ContactEmail,
		&work.CertificateRef,
	)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.CertificateJobWork{},
			ErrNotFound
	}

	if err != nil {
		return model.CertificateJobWork{},
			err
	}

	leaseExpiresAt :=
		time.Now().
			UTC().
			Add(ttl)

	_, err = tx.Exec(
		ctx,
		`
		UPDATE certificate_jobs
		SET
			status = 'claimed',
			owner_instance_id = $2::uuid,
			lease_token_hash = $3::text,
			lease_expires_at = $4::timestamptz,
			attempt = attempt + 1,
			claimed_at = now(),
			updated_at = now()
		WHERE id = $1::uuid
		`,
		work.JobID,
		ownerInstanceID,
		leaseTokenHash,
		leaseExpiresAt,
	)

	if err != nil {
		return model.CertificateJobWork{},
			err
	}

	nextCertificateStatus :=
		"issuing"

	if work.Operation == "renew" {
		nextCertificateStatus =
			"renewing"
	}
	if work.Operation == "delete" {
		nextCertificateStatus = "deleting"
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE node_certificates
		SET
			status = $2::text,
			last_error = NULL,
			updated_at = now()
		WHERE id = $1::uuid
		`,
		work.CertificateID,
		nextCertificateStatus,
	)

	if err != nil {
		return model.CertificateJobWork{},
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.CertificateJobWork{},
			err
	}

	work.LeaseExpiresAt =
		leaseExpiresAt

	return work, nil
}

func (p *Postgres) RenewCertificateJobLease(
	ctx context.Context,
	nodeID string,
	jobID string,
	ownerInstanceID string,
	leaseTokenHash string,
	ttl time.Duration,
) (
	time.Time,
	error,
) {
	leaseExpiresAt :=
		time.Now().
			UTC().
			Add(ttl)

	tag, err := p.Pool.Exec(
		ctx,
		`
		UPDATE certificate_jobs
		SET
			lease_expires_at = $5::timestamptz,
			updated_at = now()
		WHERE id = $1::uuid
		  AND node_id = $2::uuid
		  AND status = 'claimed'
		  AND owner_instance_id = $3::uuid
		  AND lease_token_hash = $4::text
		  AND lease_expires_at > now()
		`,
		jobID,
		nodeID,
		ownerInstanceID,
		leaseTokenHash,
		leaseExpiresAt,
	)

	if err != nil {
		return time.Time{}, err
	}

	if tag.RowsAffected() != 1 {
		return time.Time{},
			ErrCertificateJobLeaseConflict
	}

	return leaseExpiresAt, nil
}

func (p *Postgres) CompleteCertificateJob(
	ctx context.Context,
	nodeID string,
	report model.CertificateJobResult,
	leaseTokenHash string,
) error {
	tx, err :=
		p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var operation string

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			operation
		FROM certificate_jobs
		WHERE id = $1::uuid
		  AND certificate_id = $2::uuid
		  AND node_id = $3::uuid
		  AND status = 'claimed'
		  AND lease_token_hash = $4::text
		  AND lease_expires_at > now()
		FOR UPDATE
		`,
		report.JobID,
		report.CertificateID,
		nodeID,
		leaseTokenHash,
	).Scan(
		&operation,
	)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return ErrCertificateJobLeaseConflict
	}

	if err != nil {
		return err
	}
	if report.Success {
		if operation == "delete" {
			if report.Issuer != "" || report.FingerprintSHA256 != "" || report.NotBefore != nil || report.NotAfter != nil {
				return ErrCertificateResultInvalid
			}
		} else if report.Issuer == "" || len(report.FingerprintSHA256) != 64 || report.NotBefore == nil || report.NotAfter == nil || !report.NotAfter.After(*report.NotBefore) {
			return ErrCertificateResultInvalid
		}
	}

	if report.Success {
		_, err = tx.Exec(
			ctx,
			`
			UPDATE certificate_jobs
			SET
				status = 'completed',
				lease_token_hash = NULL,
				lease_expires_at = NULL,
				last_error = NULL,
				completed_at = now(),
				updated_at = now()
			WHERE id = $1::uuid
			`,
			report.JobID,
		)

		if err != nil {
			return err
		}

		if operation == "delete" {
			_, err = tx.Exec(ctx, `UPDATE node_certificates SET status='deleted',auto_renew=false,issuer=NULL,fingerprint_sha256=NULL,not_before=NULL,not_after=NULL,observed_at=now(),last_error=NULL,updated_at=now() WHERE id=$1::uuid AND node_id=$2::uuid`, report.CertificateID, nodeID)
		} else {
			_, err = tx.Exec(
				ctx,
				`
			UPDATE node_certificates
			SET
				status = 'active',
				issuer = $2::text,
				fingerprint_sha256 = $3::text,
				not_before = $4::timestamptz,
				not_after = $5::timestamptz,
				observed_at = now(),
				last_error = NULL,
				updated_at = now()
			WHERE id = $1::uuid
			  AND node_id = $6::uuid
			`,
				report.CertificateID,
				report.Issuer,
				report.FingerprintSHA256,
				report.NotBefore,
				report.NotAfter,
				nodeID,
			)
		}

		if err != nil {
			return err
		}
	} else {
		message :=
			report.ErrorMessage

		if message == "" {
			message =
				"certificate operation failed"
		}

		_, err = tx.Exec(
			ctx,
			`
			UPDATE certificate_jobs
			SET
				status = 'failed',
				lease_token_hash = NULL,
				lease_expires_at = NULL,
				last_error = $2::text,
				completed_at = now(),
				updated_at = now()
			WHERE id = $1::uuid
			`,
			report.JobID,
			message,
		)

		if err != nil {
			return err
		}

		nextCertificateStatus :=
			"failed"

		if operation == "renew" {
			// A failed renewal must not invalidate the
			// currently installed still-valid certificate.
			nextCertificateStatus =
				"active"
		}
		if operation == "delete" {
			nextCertificateStatus = "failed"
		}

		_, err = tx.Exec(
			ctx,
			`
			UPDATE node_certificates
			SET
				status = $2::text,
				last_error = $3::text,
				observed_at = now(),
				updated_at = now()
			WHERE id = $1::uuid
			  AND node_id = $4::uuid
			`,
			report.CertificateID,
			nextCertificateStatus,
			message,
			nodeID,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}
