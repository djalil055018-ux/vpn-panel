package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrNodeDeleteConfirmation = errors.New("exact node name and stopped server confirmation required")
var ErrNodeDeleteBusy = errors.New("node has a recent heartbeat or unresolved work")
var ErrNodeRetired = errors.New("node is deleted")

type NodeDeletion struct {
	NodeID          string    `json:"node_id"`
	Deleted         bool      `json:"deleted"`
	Decommissioning bool      `json:"decommissioning,omitempty"`
	Generation      int64     `json:"generation,omitempty"`
	DeletedAt       time.Time `json:"deleted_at"`
}

func (p *Postgres) DeleteNode(ctx context.Context, id, confirmedName string, serverStopped bool) (NodeDeletion, error) {
	return p.DeleteNodeWithOptions(ctx, id, confirmedName, serverStopped, false)
}

func (p *Postgres) DeleteNodeWithOptions(ctx context.Context, id, confirmedName string, serverStopped, decommissionOnline bool) (NodeDeletion, error) {
	out := NodeDeletion{NodeID: id}
	if !adminOwnerAllowed(ctx) {
		return out, ErrAdminPermission
	}
	if confirmedName == "" || (!serverStopped && !decommissionOnline) {
		return out, ErrNodeDeleteConfirmation
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Fleet reconciliation takes this lock before any node lock.
	if err = lockAgentFleet(ctx, tx); err != nil {
		return out, err
	}
	var tenant string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid`, id).Scan(&tenant); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	} else if err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var name, status string
	var online, healthReady bool
	var desiredGeneration, appliedGeneration int64
	if err = tx.QueryRow(ctx, `SELECT n.name,n.status,coalesce(n.last_seen_at>now()-interval '90 seconds',false),n.desired_generation,n.applied_generation,coalesce(h.healthy AND h.applied_generation=n.applied_generation AND h.checked_at>now()-interval '90 seconds',false) FROM nodes n LEFT JOIN node_health h ON h.node_id=n.id WHERE n.id=$1::uuid FOR UPDATE OF n`, id).Scan(&name, &status, &online, &desiredGeneration, &appliedGeneration, &healthReady); err != nil {
		return out, err
	}
	if name != confirmedName {
		return out, ErrNodeDeleteConfirmation
	}
	if status == "retired" {
		if err = tx.QueryRow(ctx, `SELECT retired_at FROM node_retirements WHERE node_id=$1::uuid`, id).Scan(&out.DeletedAt); err != nil {
			return out, err
		}
		out.Deleted = true
		return out, tx.Commit(ctx)
	}
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT
  EXISTS(SELECT 1 FROM deployment_execution_leases WHERE node_id=$1::uuid AND state='active')
  OR (EXISTS(SELECT 1 FROM deployments WHERE node_id=$1::uuid AND status='applying') AND NOT ($2::boolean AND NOT $3::boolean))
  OR EXISTS(SELECT 1 FROM agent_fleet_jobs j JOIN agent_fleet_runs r ON r.id=j.run_id WHERE j.node_id=$1::uuid AND (j.status='claimed' OR (j.status IN ('queued','failed') AND r.status='paused') OR (j.status='failed' AND r.status='running')))
  OR EXISTS(SELECT 1 FROM certificate_jobs WHERE node_id=$1::uuid AND status='claimed')
	OR EXISTS(SELECT 1 FROM recovery_attempts a LEFT JOIN deployments d ON d.id=a.deployment_id WHERE a.node_id=$1::uuid AND (a.status IN ('planned','approved') OR (a.status='executed' AND d.status IN ('pending','applying'))))`, id, serverStopped, online).Scan(&busy); err != nil {
		return out, err
	}
	if busy {
		return out, ErrNodeDeleteBusy
	}
	decommissionGeneration := int64(0)
	if online {
		if !decommissionOnline {
			return out, ErrNodeDeleteBusy
		}
		if status != "decommissioning" {
			if _, err = tx.Exec(ctx, `UPDATE vpn_services SET enabled=false,updated_at=now() WHERE node_id=$1::uuid AND enabled`, id); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `UPDATE node_certificates SET auto_renew=false,updated_at=now() WHERE node_id=$1::uuid AND auto_renew`, id); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `UPDATE certificate_jobs SET status='failed',last_error='node_decommissioning',completed_at=now(),updated_at=now() WHERE node_id=$1::uuid AND status='pending'`, id); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `UPDATE agent_fleet_jobs SET status='superseded',completed_at=now(),message='node_decommissioning' WHERE node_id=$1::uuid AND status='queued'`, id); err != nil {
				return out, err
			}
			state, releaseID, buildErr := buildNodeDesiredStateTx(ctx, tx, id)
			if buildErr != nil {
				return out, buildErr
			}
			if len(state.Services) != 0 {
				return out, ErrNodeDeleteBusy
			}
			if err = saveDesiredStateTx(ctx, tx, id, state, releaseID); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `UPDATE nodes SET status='decommissioning' WHERE id=$1::uuid AND status<>'retired'`, id); err != nil {
				return out, err
			}
			actorType, actorID := accessActor(ctx)
			if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'node.decommission_requested',$3,$4,jsonb_build_object('generation',$5::bigint,'services_removed',true))`, tenant, id, actorType, actorID, state.Generation); err != nil {
				return out, err
			}
			out.Decommissioning = true
			out.Generation = state.Generation
			return out, tx.Commit(ctx)
		}
		var enabledService bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE node_id=$1::uuid AND enabled)`, id).Scan(&enabledService); err != nil {
			return out, err
		}
		if enabledService || desiredGeneration <= 0 || desiredGeneration != appliedGeneration || !healthReady {
			return out, ErrNodeDeleteBusy
		}
		decommissionGeneration = desiredGeneration
	} else if !serverStopped {
		return out, ErrNodeDeleteConfirmation
	}
	if serverStopped && !online {
		if err = failApplyingDeploymentsForStoppedNode(ctx, tx, tenant, id); err != nil {
			return out, err
		}
	}
	// Cancel only work never claimed. Preserve all execution receipts and fences.
	for _, query := range []string{
		`UPDATE vpn_services SET enabled=false,updated_at=now() WHERE node_id=$1::uuid AND enabled`,
		`UPDATE node_certificates SET auto_renew=false,updated_at=now() WHERE node_id=$1::uuid AND auto_renew`,
		`UPDATE certificate_jobs SET status='failed',last_error='node_retired',completed_at=now(),updated_at=now() WHERE node_id=$1::uuid AND status='pending'`,
		`UPDATE agent_fleet_jobs SET status='superseded',completed_at=now(),message='node_retired' WHERE node_id=$1::uuid AND status='queued'`,
	} {
		if _, err = tx.Exec(ctx, query, id); err != nil {
			return out, err
		}
	}
	if err = tx.QueryRow(ctx, `INSERT INTO node_retirements(node_id,confirmed_name,server_stopped,decommission_generation) VALUES($1::uuid,$2,$3,NULLIF($4::bigint,0)) RETURNING retired_at`, id, name, serverStopped, decommissionGeneration).Scan(&out.DeletedAt); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE nodes SET status='retired',agent_token_hash=NULL,bootstrap_token_hash=NULL WHERE id=$1::uuid`, id); err != nil {
		return out, err
	}
	if err = reconcileAgentFleet(ctx, tx); err != nil {
		return out, err
	}
	actorType, actorID := accessActor(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'node.deleted',$3,$4,jsonb_build_object('node_id',$2::text,'history_preserved',true,'server_stopped_attested',$5::boolean,'decommission_generation',NULLIF($6::bigint,0)))`, tenant, id, actorType, actorID, serverStopped, decommissionGeneration); err != nil {
		return out, err
	}
	out.Deleted = true
	return out, tx.Commit(ctx)
}

// A stopped, unreachable node can retain old deployments in "applying" even
// after every execution lease has ended. Close those historical attempts in
// the same retirement transaction so an inert rollout row cannot prevent the
// owner from retiring the node forever. Active leases and recovery work are
// rejected before this helper is reached; online nodes still use the normal
// empty-generation decommission path.
func failApplyingDeploymentsForStoppedNode(ctx context.Context, tx pgx.Tx, tenantID, nodeID string) error {
	const reason = "node_retired_before_deployment_converged"
	type deployment struct {
		id         string
		generation int64
	}
	rows, err := tx.Query(ctx, `UPDATE deployments
SET status='failed',error_message=$2,completed_at=now(),updated_at=now()
WHERE node_id=$1::uuid AND status='applying'
RETURNING id::text,generation`, nodeID, reason)
	if err != nil {
		return err
	}
	var failed []deployment
	for rows.Next() {
		var item deployment
		if err = rows.Scan(&item.id, &item.generation); err != nil {
			rows.Close()
			return err
		}
		failed = append(failed, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	actorType, actorID := accessActor(ctx)
	for _, item := range failed {
		if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload)
VALUES($1::uuid,$2::uuid,'deployment.failed',$3,$4,jsonb_build_object('deployment_id',$5::text,'generation',$6::bigint,'previous_status','applying','status','failed','error_message',$7::text))`, tenantID, nodeID, actorType, actorID, item.id, item.generation, reason); err != nil {
			return err
		}
		var planID, previousOutcome string
		err = tx.QueryRow(ctx, `SELECT id::text,COALESCE(outcome_status,'') FROM rollout_plans WHERE deployment_id=$1::uuid AND status='executed' FOR UPDATE`, item.id).Scan(&planID, &previousOutcome)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE rollout_plans SET outcome_status='failed',outcome_at=now(),outcome_reason=$2,updated_at=now()
WHERE id=$1::uuid AND (outcome_status IS NULL OR outcome_status IN ('pending','applying'))`, planID, reason)
		if updateErr != nil {
			return updateErr
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload)
VALUES($1::uuid,$2::uuid,'rollout_plan.outcome_changed',$3,$4,jsonb_build_object('rollout_plan_id',$5::text,'deployment_id',$6::text,'generation',$7::bigint,'previous_status',$8::text,'outcome_status','failed','error_message',$9::text))`, tenantID, nodeID, actorType, actorID, planID, item.id, item.generation, previousOutcome, reason); err != nil {
			return err
		}
	}
	return nil
}
