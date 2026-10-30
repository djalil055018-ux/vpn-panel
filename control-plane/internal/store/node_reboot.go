package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"vpn-platform/internal/model"
)

var (
	ErrNodeRebootNotReady      = errors.New("node is not ready to reboot")
	ErrNodeRebootActive        = errors.New("node already has an active reboot request")
	ErrNodeRebootCooldown      = errors.New("node was rebooted recently")
	ErrNodeRebootAgentRequired = errors.New("node agent does not support reboot requests")
	ErrNodeRebootJobNotFound   = errors.New("node reboot job not found")
	ErrNodeRebootResultInvalid = errors.New("node reboot result is invalid")
)

func (p *Postgres) QueueNodeReboot(ctx context.Context, nodeID, confirmedName string) (model.NodeRebootJob, error) {
	var out model.NodeRebootJob
	if !adminOwnerAllowed(ctx) {
		return out, ErrAdminPermission
	}
	confirmedName = strings.TrimSpace(confirmedName)
	if confirmedName == "" {
		return out, ErrNodeRebootNotReady
	}

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	var tenantID, name, status, agentVersion string
	var lastSeen time.Time
	var desired, applied int64
	var registered, online, healthy bool
	if err = tx.QueryRow(ctx, `
		SELECT n.tenant_id::text,n.name,n.status,COALESCE(n.agent_version,''),
		       n.desired_generation,n.applied_generation,
	       COALESCE(n.last_seen_at,'epoch'::timestamptz),
		       n.agent_token_hash IS NOT NULL,
		       n.last_seen_at >= now() - interval '2 minutes',
		       COALESCE(h.healthy,false)
		         AND h.checked_at >= now() - interval '3 minutes'
		         AND h.applied_generation=n.applied_generation
		FROM nodes n
	LEFT JOIN node_health h ON h.node_id=n.id
	WHERE n.id=$1::uuid
	FOR UPDATE OF n`, nodeID).Scan(&tenantID, &name, &status, &agentVersion, &desired, &applied, &lastSeen, &registered, &online, &healthy); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	} else if err != nil {
		return out, err
	}
	if status != "online" || !registered || !online || !healthy || desired == 0 || desired != applied {
		return out, ErrNodeRebootNotReady
	}
	var agentSupportsReboot bool
	if err = tx.QueryRow(ctx, `SELECT COALESCE(agent_version_rank($1) >= agent_version_rank('0.2.39'),false)`, agentVersion).Scan(&agentSupportsReboot); err != nil {
		return out, err
	}
	if !agentSupportsReboot {
		return out, ErrNodeRebootAgentRequired
	}
	if name != confirmedName {
		return out, ErrNodeNameConflict
	}

	var busy bool
	err = tx.QueryRow(ctx, `
		SELECT
		  EXISTS(SELECT 1 FROM deployments WHERE node_id=$1::uuid AND status IN ('pending','applying'))
		  OR EXISTS(SELECT 1 FROM certificate_jobs WHERE node_id=$1::uuid AND status IN ('pending','claimed'))
		  OR EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE node_id=$1::uuid AND status IN ('queued','claimed'))
		  OR EXISTS(SELECT 1 FROM recovery_attempts WHERE node_id=$1::uuid AND status IN ('planned','approved'))
		  OR EXISTS(SELECT 1 FROM node_reboot_jobs WHERE node_id=$1::uuid AND status IN ('queued','claimed'))`, nodeID).Scan(&busy)
	if err != nil {
		return out, err
	}
	if busy {
		return out, ErrNodeRebootActive
	}
	var recent bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_reboot_jobs WHERE node_id=$1::uuid AND status='scheduled' AND scheduled_at > now()-interval '15 minutes')`, nodeID).Scan(&recent); err != nil {
		return out, err
	}
	if recent {
		return out, ErrNodeRebootCooldown
	}

	actorType, actorID := accessActor(ctx)
	out.NodeID = nodeID
	out.NodeName = name
	err = tx.QueryRow(ctx, `
		INSERT INTO node_reboot_jobs(tenant_id,node_id,requested_by,requested_last_seen_at)
		VALUES($1::uuid,$2::uuid,$3,$4)
		RETURNING id::text,status,created_at`, tenantID, nodeID, actorID, lastSeen).Scan(&out.ID, &out.Status, &out.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return out, ErrNodeRebootActive
		}
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'node.reboot.requested',$3,$4,jsonb_build_object('job_id',$5::text,'generation',$6::bigint))`, tenantID, nodeID, actorType, actorID, out.ID, desired); err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func (p *Postgres) ClaimNodeRebootJob(ctx context.Context, nodeID, ownerInstanceID string) (model.NodeRebootJobGrant, error) {
	var out model.NodeRebootJobGrant
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	// A queued request must never reboot a node after it has gone stale, become
	// unhealthy, or entered another maintenance operation. Fail it before
	// claiming so a later recovery cannot trigger an unexpected reboot.
	_, err = tx.Exec(ctx, `
		UPDATE node_reboot_jobs j
		SET status='failed',
		    failure_code=CASE
		      WHEN j.created_at <= now()-interval '2 minutes' THEN 'request_expired'
		      WHEN n.status<>'online' OR n.agent_token_hash IS NULL
		        OR n.last_seen_at < now()-interval '2 minutes'
		        OR n.desired_generation=0 OR n.desired_generation<>n.applied_generation
		        OR COALESCE(h.healthy,false)=false
		        OR h.checked_at < now()-interval '3 minutes'
		        OR h.applied_generation<>n.applied_generation
		        OR COALESCE(agent_version_rank(n.agent_version)>=agent_version_rank('0.2.39'),false)=false
		        THEN 'node_not_ready'
		      ELSE 'operation_in_progress'
		    END,
		    completed_at=now()
		FROM nodes n
		LEFT JOIN node_health h ON h.node_id=n.id
		WHERE j.node_id=$1::uuid AND j.status='queued' AND n.id=j.node_id
		  AND (j.created_at <= now()-interval '2 minutes'
		    OR n.status<>'online' OR n.agent_token_hash IS NULL
		    OR n.last_seen_at < now()-interval '2 minutes'
		    OR n.desired_generation=0 OR n.desired_generation<>n.applied_generation
		    OR COALESCE(h.healthy,false)=false
		    OR h.checked_at < now()-interval '3 minutes'
		    OR h.applied_generation<>n.applied_generation
		    OR COALESCE(agent_version_rank(n.agent_version)>=agent_version_rank('0.2.39'),false)=false
		    OR EXISTS(SELECT 1 FROM deployments d WHERE d.node_id=n.id AND d.status IN ('pending','applying'))
		    OR EXISTS(SELECT 1 FROM certificate_jobs c WHERE c.node_id=n.id AND c.status IN ('pending','claimed'))
		    OR EXISTS(SELECT 1 FROM agent_fleet_jobs f WHERE f.node_id=n.id AND f.status IN ('queued','claimed'))
		    OR EXISTS(SELECT 1 FROM recovery_attempts r WHERE r.node_id=n.id AND r.status IN ('planned','approved')))
	`, nodeID)
	if err != nil {
		return out, err
	}

	err = tx.QueryRow(ctx, `
		SELECT j.id::text
		FROM node_reboot_jobs j
		JOIN nodes n ON n.id=j.node_id
		JOIN node_health h ON h.node_id=n.id
		WHERE j.node_id=$1::uuid AND j.status='queued'
		  AND j.created_at > now()-interval '2 minutes'
		  AND n.status='online' AND n.agent_token_hash IS NOT NULL
		  AND n.last_seen_at >= now()-interval '2 minutes'
		  AND n.desired_generation>0 AND n.desired_generation=n.applied_generation
		  AND h.healthy AND h.checked_at >= now()-interval '3 minutes'
		  AND h.applied_generation=n.applied_generation
		  AND COALESCE(agent_version_rank(n.agent_version)>=agent_version_rank('0.2.39'),false)
		  AND NOT EXISTS(SELECT 1 FROM deployments d WHERE d.node_id=n.id AND d.status IN ('pending','applying'))
		  AND NOT EXISTS(SELECT 1 FROM certificate_jobs c WHERE c.node_id=n.id AND c.status IN ('pending','claimed'))
		  AND NOT EXISTS(SELECT 1 FROM agent_fleet_jobs f WHERE f.node_id=n.id AND f.status IN ('queued','claimed'))
		  AND NOT EXISTS(SELECT 1 FROM recovery_attempts r WHERE r.node_id=n.id AND r.status IN ('planned','approved'))
		ORDER BY j.created_at,j.id
		FOR UPDATE OF j,n SKIP LOCKED
		LIMIT 1`, nodeID).Scan(&out.JobID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return out, err
		}
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE node_reboot_jobs SET status='claimed',owner_instance_id=$2::uuid,claimed_at=now() WHERE id=$1::uuid AND status='queued'`, out.JobID, ownerInstanceID); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func (p *Postgres) ReportNodeRebootJob(ctx context.Context, nodeID string, result model.NodeRebootJobResult) error {
	if result.Status != "scheduled" && result.Status != "failed" {
		return ErrNodeRebootResultInvalid
	}
	if result.Status == "failed" && result.FailureCode != "scheduler_unavailable" {
		return ErrNodeRebootResultInvalid
	}
	if result.Status == "scheduled" && result.FailureCode != "" {
		return ErrNodeRebootResultInvalid
	}
	var completed any
	var scheduled any
	if result.Status == "scheduled" {
		scheduled = time.Now().UTC()
	} else {
		completed = time.Now().UTC()
	}
	commandTag, err := p.Pool.Exec(ctx, `
		UPDATE node_reboot_jobs
		SET status=$4,scheduled_at=$5,completed_at=$6,failure_code=NULLIF($7,'')
		WHERE id=$1::uuid AND node_id=$2::uuid AND owner_instance_id=$3::uuid AND status='claimed'`, result.JobID, nodeID, result.OwnerInstanceID, result.Status, scheduled, completed, result.FailureCode)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNodeRebootJobNotFound
	}
	return nil
}
