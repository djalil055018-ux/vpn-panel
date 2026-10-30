package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

func (p *Postgres) SetCertificateAutoRenew(ctx context.Context, id string, enabled bool) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM node_certificates WHERE id=$1::uuid FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (status == "revoked" || status == "deleted" || status == "deleting") {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if enabled {
		held, err := importedTLSRenewalHeld(ctx, tx, id)
		if err != nil {
			return err
		}
		if held {
			return ErrCertificateJobInvalidState
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE node_certificates SET auto_renew=$2,updated_at=now() WHERE id=$1::uuid`, id, enabled); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Archive disables management/renewal. It does not claim CA revocation or delete
// the installed material, which may still be used by an external service.
func (p *Postgres) ArchiveNodeCertificate(ctx context.Context, id string) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM node_certificates WHERE id=$1::uuid FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status == "deleted" || status == "deleting" {
		return ErrNotFound
	}
	var busy bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificate_jobs WHERE certificate_id=$1::uuid AND status IN ('pending','claimed'))`, id).Scan(&busy)
	if err != nil {
		return err
	}
	if busy {
		return ErrCertificateJobExists
	}
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_service_tls WHERE certificate_id=$1::uuid)`, id).Scan(&busy)
	if err != nil {
		return err
	}
	if busy {
		return ErrCertificateInUse
	}
	_, err = tx.Exec(ctx, `UPDATE node_certificates SET status='revoked',auto_renew=false,updated_at=now() WHERE id=$1::uuid`, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) ListCertificateJobs(ctx context.Context, id string) ([]model.CertificateJob, error) {
	var exists bool
	err := p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_certificates WHERE id=$1::uuid)`, id).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT id::text,tenant_id::text,node_id::text,certificate_id::text,operation,status,owner_instance_id::text,lease_expires_at,attempt,last_error,created_at,claimed_at,completed_at,updated_at
		FROM certificate_jobs WHERE certificate_id=$1::uuid ORDER BY created_at DESC,id DESC LIMIT 30`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []model.CertificateJob{}
	for rows.Next() {
		j, err := scanCertificateJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// Rechecked under the per-certificate lock by queueCertificateJob, so concurrent
// timers, a manual renewal and disabling auto-renew cannot enqueue stale work.
func (p *Postgres) QueueDueCertificateRenewals(ctx context.Context) (int, error) {
	rows, err := p.Pool.Query(ctx, `SELECT id::text FROM node_certificates c WHERE auto_renew AND status='active' AND not_after<=now()+interval '30 days'
		AND NOT EXISTS(SELECT 1 FROM certificate_jobs j WHERE j.certificate_id=c.id AND j.operation='renew' AND j.created_at>now()-interval '6 hours')
		ORDER BY not_after,id LIMIT 100`)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		_, err := p.queueCertificateJob(ctx, id, "renew", true)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCertificateJobExists) || errors.Is(err, ErrCertificateJobInvalidState) {
			continue
		}
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
