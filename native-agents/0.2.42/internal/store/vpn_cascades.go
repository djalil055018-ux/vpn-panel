package store

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/model"
)

var cascadeIdentifier = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func cascadeSQLError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23503" || pg.Code == "23514") {
		return ErrVPNCascade
	}
	return err
}

func (p *Postgres) ListVPNCascades(ctx context.Context, tenant string) ([]model.VPNCascade, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+cascadeColumns+` FROM vpn_cascades WHERE tenant_id=$1::uuid ORDER BY created_at,id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.VPNCascade{}
	for rows.Next() {
		c, err := scanCascade(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) GetVPNCascade(ctx context.Context, id string) (model.VPNCascade, error) {
	c, err := scanCascade(p.Pool.QueryRow(ctx, `SELECT `+cascadeColumns+` FROM vpn_cascades WHERE id=$1::uuid`, id))
	if err != nil {
		return c, err
	}
	if !tenantScopeAllowed(ctx, c.TenantID) {
		return model.VPNCascade{}, ErrNotFound
	}
	return c, nil
}

// Empty id creates a cascade. Updates replace its editable definition; no
// caller can provide the private transit identity, raw routing or credentials.
func (p *Postgres) PutVPNCascade(ctx context.Context, tenant, id string, input model.VPNCascadeInput) (out model.VPNCascadeMutation, err error) {
	defer func() { err = cascadeSQLError(err) }()
	out.Rebuilds = []model.NodeRebuildResult{}
	if !tenantScopeAllowed(ctx, tenant) {
		return out, ErrNotFound
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 128 || !model.ValidSubscriptionName(input.Name) || !cascadeIdentifier.MatchString(input.PlanID) || !cascadeIdentifier.MatchString(input.EntryServiceID) || !cascadeIdentifier.MatchString(input.ExitServiceID) || input.EntryPort < 1 || input.EntryPort > 65535 || input.EntryPort == 10085 || (id != "" && !cascadeIdentifier.MatchString(id)) {
		return out, ErrVPNCascade
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var before *model.VPNCascade
	if id != "" {
		c, e := scanCascade(tx.QueryRow(ctx, `SELECT `+cascadeColumns+` FROM vpn_cascades WHERE id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, id, tenant))
		if e != nil {
			return out, e
		}
		before = &c
	}
	var plan string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM vpn_access_plans WHERE id=$1::uuid AND tenant_id=$2::uuid FOR KEY SHARE`, input.PlanID, tenant).Scan(&plan); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	} else if err != nil {
		return out, err
	}
	nodes := []string{}
	for _, service := range []string{input.EntryServiceID, input.ExitServiceID} {
		var node string
		err = tx.QueryRow(ctx, `SELECT s.node_id::text FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id WHERE s.id=$1::uuid AND s.tenant_id=$2::uuid AND s.protocol='vless' AND s.transport='tcp' AND s.security='reality' AND n.runtime_core='xray' AND n.status<>'retired' FOR KEY SHARE OF s`, service, tenant).Scan(&node)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrVPNCascade
		}
		if err != nil {
			return out, err
		}
		nodes = append(nodes, node)
	}
	if nodes[0] == nodes[1] {
		return out, ErrVPNCascade
	}
	var conflict bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE node_id=$1::uuid AND port=$2) OR EXISTS(SELECT 1 FROM vpn_cascades WHERE entry_node_id=$1::uuid AND entry_port=$2 AND id::text<>$3)`, nodes[0], input.EntryPort, id).Scan(&conflict)
	if err != nil {
		return out, err
	}
	if conflict {
		return out, ErrVPNCascade
	}
	if before != nil && before.Name == input.Name && before.PlanID == input.PlanID && before.EntryServiceID == input.EntryServiceID && before.ExitServiceID == input.ExitServiceID && before.EntryPort == input.EntryPort && before.Enabled == input.Enabled {
		out.Cascade = before
		return out, tx.Commit(ctx)
	}
	var c model.VPNCascade
	if before == nil {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM vpn_cascades WHERE tenant_id=$1::uuid`, tenant).Scan(&count); err != nil {
			return out, err
		}
		if count >= 64 {
			return out, ErrVPNCascade
		}
		c, err = scanCascade(tx.QueryRow(ctx, `INSERT INTO vpn_cascades(tenant_id,name,plan_id,entry_service_id,exit_service_id,entry_node_id,exit_node_id,entry_port,enabled) VALUES($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::uuid,$8,$9) RETURNING `+cascadeColumns, tenant, input.Name, input.PlanID, input.EntryServiceID, input.ExitServiceID, nodes[0], nodes[1], input.EntryPort, input.Enabled))
	} else {
		c, err = scanCascade(tx.QueryRow(ctx, `UPDATE vpn_cascades SET name=$2,plan_id=$3::uuid,entry_service_id=$4::uuid,exit_service_id=$5::uuid,entry_node_id=$6::uuid,exit_node_id=$7::uuid,entry_port=$8,enabled=$9,updated_at=now() WHERE id=$1::uuid RETURNING `+cascadeColumns, id, input.Name, input.PlanID, input.EntryServiceID, input.ExitServiceID, nodes[0], nodes[1], input.EntryPort, input.Enabled))
	}
	if err != nil {
		return out, err
	}
	out.Cascade = &c
	out.Changed = true
	runtimeChanged := before == nil || before.PlanID != c.PlanID || before.EntryServiceID != c.EntryServiceID || before.ExitServiceID != c.ExitServiceID || before.EntryPort != c.EntryPort || before.Enabled != c.Enabled
	if runtimeChanged && (c.Enabled || before != nil && before.Enabled) {
		if before != nil {
			nodes = append(nodes, before.EntryNodeID, before.ExitNodeID)
		}
		out.Rebuilds, err = rebuildCascadeNodesTx(ctx, tx, nodes)
		if err != nil {
			return out, err
		}
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_cascade.saved',$2,$3,jsonb_build_object('cascade_id',$4::text,'rebuild_count',$5::integer))`, tenant, actor, actorID, c.ID, len(out.Rebuilds))
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func rebuildCascadeNodesTx(ctx context.Context, tx pgx.Tx, nodes []string) ([]model.NodeRebuildResult, error) {
	set := map[string]bool{}
	for _, node := range nodes {
		set[node] = true
	}
	ordered := []string{}
	for node := range set {
		ordered = append(ordered, node)
	}
	sort.Strings(ordered)
	out := []model.NodeRebuildResult{}
	for _, node := range ordered {
		state, release, err := buildNodeDesiredStateTx(ctx, tx, node)
		if err != nil {
			return nil, err
		}
		if err = saveDesiredStateTx(ctx, tx, node, state, release); err != nil {
			return nil, err
		}
		out = append(out, model.NodeRebuildResult{NodeID: node, Generation: state.Generation})
	}
	return out, nil
}

func (p *Postgres) DeleteVPNCascade(ctx context.Context, id string) (model.VPNCascadeMutation, error) {
	out := model.VPNCascadeMutation{Rebuilds: []model.NodeRebuildResult{}}
	c, err := p.GetVPNCascade(ctx, id)
	if err != nil {
		return out, err
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockTenantAccess(ctx, tx, c.TenantID); err != nil {
		return out, err
	}
	c, err = scanCascade(tx.QueryRow(ctx, `SELECT `+cascadeColumns+` FROM vpn_cascades WHERE id=$1::uuid FOR UPDATE`, id))
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM vpn_cascades WHERE id=$1::uuid`, id); err != nil {
		return out, err
	}
	if c.Enabled {
		out.Rebuilds, err = rebuildCascadeNodesTx(ctx, tx, []string{c.EntryNodeID, c.ExitNodeID})
		if err != nil {
			return out, err
		}
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_cascade.deleted',$2,$3,jsonb_build_object('cascade_id',$4::text,'rebuild_count',$5::integer))`, c.TenantID, actor, actorID, id, len(out.Rebuilds))
	if err != nil {
		return out, err
	}
	out.Changed = true
	return out, tx.Commit(ctx)
}
