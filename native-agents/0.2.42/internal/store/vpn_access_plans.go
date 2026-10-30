package store

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

const accessPlanColumns = `id::text, tenant_id::text, name, code, enabled, created_at, updated_at`

func scanAccessPlan(row pgx.Row) (model.VPNAccessPlan, error) {
	var p model.VPNAccessPlan
	err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Code, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return p, err
}

func (p *Postgres) CreateVPNAccessPlan(ctx context.Context, tenantID, name, code string, enabled bool) (model.VPNAccessPlan, error) {
	if !tenantScopeAllowed(ctx, tenantID) {
		return model.VPNAccessPlan{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.VPNAccessPlan{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = checkTenantQuota(ctx, tx, tenantID, "plan"); err != nil {
		return model.VPNAccessPlan{}, err
	}
	plan, err := scanAccessPlan(tx.QueryRow(ctx, `INSERT INTO vpn_access_plans(tenant_id,name,code,enabled)
		SELECT id,$2,$3,$4 FROM tenants WHERE id=$1::uuid RETURNING `+accessPlanColumns, tenantID, name, code, enabled))
	if err != nil {
		return plan, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'access_plan.created',$2,$3,jsonb_build_object('plan_id',$4::text))`, tenantID, actorType, actorID, plan.ID)
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit(ctx)
}

func (p *Postgres) ListVPNAccessPlans(ctx context.Context, tenantID string) ([]model.VPNAccessPlan, error) {
	if !tenantScopeAllowed(ctx, tenantID) {
		return nil, ErrNotFound
	}
	var exists bool
	if err := p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, tenantID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+accessPlanColumns+` FROM vpn_access_plans WHERE tenant_id=$1::uuid ORDER BY code,id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := make([]model.VPNAccessPlan, 0)
	for rows.Next() {
		plan, err := scanAccessPlan(rows)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (p *Postgres) GetVPNAccessPlan(ctx context.Context, id string) (model.VPNAccessPlanDetail, error) {
	// One snapshot prevents a detail response from mixing concurrent membership versions.
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return model.VPNAccessPlanDetail{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	plan, err := scanAccessPlan(tx.QueryRow(ctx, `SELECT `+accessPlanColumns+` FROM vpn_access_plans WHERE id=$1::uuid`, id))
	if err != nil {
		return model.VPNAccessPlanDetail{}, err
	}
	if !tenantScopeAllowed(ctx, plan.TenantID) {
		return model.VPNAccessPlanDetail{}, ErrNotFound
	}
	detail := model.VPNAccessPlanDetail{VPNAccessPlan: plan, ServiceIDs: []string{}, ClientIDs: []string{}, BotClientIDs: []string{}}
	for _, part := range []struct {
		query string
		dest  *[]string
	}{
		{`SELECT service_id::text FROM vpn_access_plan_services WHERE plan_id=$1::uuid ORDER BY service_id`, &detail.ServiceIDs},
		{`SELECT client_id::text FROM vpn_client_access_plans WHERE plan_id=$1::uuid ORDER BY client_id`, &detail.ClientIDs},
		{`SELECT client_id::text FROM vpn_bot_client_access_plans WHERE plan_id=$1::uuid ORDER BY client_id`, &detail.BotClientIDs},
	} {
		rows, err := tx.Query(ctx, part.query, id)
		if err != nil {
			return detail, err
		}
		for rows.Next() {
			var value string
			if err = rows.Scan(&value); err != nil {
				rows.Close()
				return detail, err
			}
			*part.dest = append(*part.dest, value)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return detail, err
		}
	}
	return detail, tx.Commit(ctx)
}

type AccessPlanUpdate struct {
	Name    *string
	Code    *string
	Enabled *bool
}

// Candidate nodes are collected before AND after mutation, so removals and
// disabling a plan cannot lose the nodes that must revoke access.
func accessPlanNodes(ctx context.Context, tx pgx.Tx, id string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT s.node_id::text
		FROM vpn_access_plans ap JOIN vpn_access_plan_services ps ON ps.plan_id=ap.id AND ps.tenant_id=ap.tenant_id
		JOIN vpn_services s ON s.id=ps.service_id AND s.tenant_id=ps.tenant_id
		WHERE ap.id=$1::uuid AND ap.enabled AND s.enabled AND EXISTS (
		 SELECT 1 FROM vpn_clients c WHERE c.tenant_id=ap.tenant_id AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now()) AND (
		 EXISTS(SELECT 1 FROM vpn_client_access_plans cp WHERE cp.plan_id=ap.id AND cp.client_id=c.id AND cp.tenant_id=ap.tenant_id)
		 OR EXISTS(SELECT 1 FROM billing_entitlements be WHERE be.plan_id=ap.id AND be.client_id=c.id AND be.tenant_id=ap.tenant_id AND be.expires_at>now())
   OR EXISTS(SELECT 1 FROM vpn_bot_client_access_plans bp WHERE bp.plan_id=ap.id AND bp.client_id=c.id AND bp.tenant_id=ap.tenant_id)))
 UNION SELECT entry_node_id::text FROM vpn_cascades WHERE plan_id=$1::uuid AND enabled
 UNION SELECT exit_node_id::text FROM vpn_cascades WHERE plan_id=$1::uuid AND enabled`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Mutation, desired states, deployments and audit event commit atomically.
// Plan locks serialize memberships; sorted node locks serialize overlapping plans.
func (p *Postgres) mutateAccessPlan(ctx context.Context, id, event string, rebuild bool, change func(pgx.Tx, *model.VPNAccessPlan) (bool, error)) (model.VPNAccessPlanMutation, error) {
	result := model.VPNAccessPlanMutation{Rebuilds: []model.NodeRebuildResult{}}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM vpn_access_plans WHERE id=$1::uuid`, id).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return result, ErrNotFound
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return result, err
	}
	plan, err := scanAccessPlan(tx.QueryRow(ctx, `SELECT `+accessPlanColumns+` FROM vpn_access_plans WHERE id=$1::uuid FOR UPDATE`, id))
	if err != nil {
		return result, err
	}
	if !tenantScopeAllowed(ctx, plan.TenantID) {
		return result, ErrNotFound
	}
	var before []string
	if rebuild {
		before, err = accessPlanNodes(ctx, tx, id)
		if err != nil {
			return result, err
		}
	}
	changed, err := change(tx, &plan)
	if err != nil {
		return result, err
	}
	result.Changed = changed
	if event != "deleted" {
		result.Plan = &plan
	}
	if changed && rebuild {
		after, err := accessPlanNodes(ctx, tx, id)
		if err != nil {
			return result, err
		}
		set := map[string]bool{}
		for _, node := range append(before, after...) {
			set[node] = true
		}
		nodes := make([]string, 0, len(set))
		for node := range set {
			nodes = append(nodes, node)
		}
		sort.Strings(nodes)
		for _, node := range nodes {
			state, release, err := buildNodeDesiredStateTx(ctx, tx, node)
			if err != nil {
				return result, err
			}
			if err = saveDesiredStateTx(ctx, tx, node, state, release); err != nil {
				return result, err
			}
			result.Rebuilds = append(result.Rebuilds, model.NodeRebuildResult{NodeID: node, Generation: state.Generation})
		}
	}
	if changed {
		actorType, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload)
		VALUES($1::uuid,$2,$5,$6,jsonb_build_object('plan_id',$3::text,'rebuild_count',$4::integer))`, plan.TenantID, "access_plan."+event, id, len(result.Rebuilds), actorType, actorID)
		if err != nil {
			return result, err
		}
	}
	return result, tx.Commit(ctx)
}

func (p *Postgres) UpdateVPNAccessPlan(ctx context.Context, id string, input AccessPlanUpdate) (model.VPNAccessPlanMutation, error) {
	return p.mutateAccessPlan(ctx, id, "updated", input.Enabled != nil, func(tx pgx.Tx, plan *model.VPNAccessPlan) (bool, error) {
		name, code, enabled := plan.Name, plan.Code, plan.Enabled
		if input.Name != nil {
			name = *input.Name
		}
		if input.Code != nil {
			code = *input.Code
		}
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		if name == plan.Name && code == plan.Code && enabled == plan.Enabled {
			return false, nil
		}
		updated, err := scanAccessPlan(tx.QueryRow(ctx, `UPDATE vpn_access_plans SET name=$2,code=$3,enabled=$4,updated_at=now() WHERE id=$1::uuid RETURNING `+accessPlanColumns, id, name, code, enabled))
		*plan = updated
		return true, err
	})
}

func (p *Postgres) DeleteVPNAccessPlan(ctx context.Context, id string) (model.VPNAccessPlanMutation, error) {
	return p.mutateAccessPlan(ctx, id, "deleted", true, func(tx pgx.Tx, _ *model.VPNAccessPlan) (bool, error) {
		_, err := tx.Exec(ctx, `DELETE FROM vpn_access_plans WHERE id=$1::uuid`, id)
		return true, err
	})
}

func (p *Postgres) SetVPNAccessPlanService(ctx context.Context, id, serviceID string, attach bool) (model.VPNAccessPlanMutation, error) {
	return p.mutateAccessPlan(ctx, id, "service_changed", true, func(tx pgx.Tx, plan *model.VPNAccessPlan) (bool, error) {
		var found string
		err := tx.QueryRow(ctx, `SELECT id::text FROM vpn_services WHERE id=$1::uuid AND tenant_id=$2::uuid FOR KEY SHARE`, serviceID, plan.TenantID).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		query := `DELETE FROM vpn_access_plan_services WHERE plan_id=$1::uuid AND service_id=$2::uuid AND tenant_id=$3::uuid`
		if attach {
			query = `INSERT INTO vpn_access_plan_services(plan_id,service_id,tenant_id) VALUES($1::uuid,$2::uuid,$3::uuid) ON CONFLICT DO NOTHING`
		}
		tag, err := tx.Exec(ctx, query, id, serviceID, plan.TenantID)
		return tag.RowsAffected() > 0, err
	})
}

func (p *Postgres) SetVPNClientAccessPlan(ctx context.Context, id, clientID string, attach bool) (model.VPNAccessPlanMutation, error) {
	return p.mutateAccessPlan(ctx, id, "client_changed", true, func(tx pgx.Tx, plan *model.VPNAccessPlan) (bool, error) {
		var found string
		err := tx.QueryRow(ctx, `SELECT id::text FROM vpn_clients WHERE id=$1::uuid AND tenant_id=$2::uuid FOR KEY SHARE`, clientID, plan.TenantID).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		query := `DELETE FROM vpn_client_access_plans WHERE plan_id=$1::uuid AND client_id=$2::uuid AND tenant_id=$3::uuid`
		if attach {
			query = `INSERT INTO vpn_client_access_plans(plan_id,client_id,tenant_id) VALUES($1::uuid,$2::uuid,$3::uuid) ON CONFLICT DO NOTHING`
		}
		tag, err := tx.Exec(ctx, query, id, clientID, plan.TenantID)
		return tag.RowsAffected() > 0, err
	})
}
