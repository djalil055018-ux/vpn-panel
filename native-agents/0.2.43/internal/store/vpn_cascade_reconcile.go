package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

// Covers wall-clock expiry, endpoint/key changes and stale grants from deleted
// definitions. Only actual overlay changes publish a new generation.
func (p *Postgres) ReconcileVPNCascades(ctx context.Context) (int, error) {
	rows, err := p.Pool.Query(ctx, `SELECT n.id::text FROM nodes n WHERE n.status<>'retired' AND (
 EXISTS(SELECT 1 FROM vpn_active_cascades c WHERE c.entry_node_id=n.id OR c.exit_node_id=n.id)
 OR EXISTS(SELECT 1 FROM desired_states d WHERE d.node_id=n.id AND d.generation=n.desired_generation AND d.document->'xray_cascades' IS NOT NULL)) ORDER BY n.id LIMIT 128`)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
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
	var failures error
	for _, id := range ids {
		changed, e := p.reconcileCascadeNode(ctx, id)
		if e != nil {
			failures = errors.Join(failures, e)
		} else if changed {
			count++
		}
	}
	return count, failures
}

func (p *Postgres) reconcileCascadeNode(ctx context.Context, id string) (bool, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid AND status<>'retired'`, id).Scan(&tenant); errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return false, err
	}
	state, release, err := buildNodeDesiredStateTx(ctx, tx, id)
	if err != nil {
		return false, err
	}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT ds.document FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation WHERE n.id=$1::uuid`, id).Scan(&raw); err != nil {
		return false, err
	}
	var prior model.DesiredState
	if json.Unmarshal(raw, &prior) != nil {
		return false, ErrVPNCascadeIdentity
	}
	a, _ := json.Marshal(prior.XrayCascades)
	b, _ := json.Marshal(state.XrayCascades)
	if bytes.Equal(a, b) {
		return false, tx.Commit(ctx)
	}
	if err = saveDesiredStateTx(ctx, tx, id, state, release); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
