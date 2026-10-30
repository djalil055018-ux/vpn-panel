package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

// Commit traffic independently from current runtime health. Retried delivery
// must not refresh liveness, online-address freshness or applied generations.
func (p *Postgres) SaveTrafficDelivery(ctx context.Context, nodeID string, delivery model.TrafficDelivery) error {
	if delivery.RecordedAt.IsZero() || delivery.RecordedAt.Year() < 2000 || delivery.RecordedAt.After(time.Now().Add(5*time.Minute)) {
		return errors.New("invalid traffic collection time")
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&tenant); err != nil {
		return err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return err
	}
	var retired bool
	if err = tx.QueryRow(ctx, `SELECT status='retired' FROM nodes WHERE id=$1::uuid FOR SHARE`, nodeID).Scan(&retired); err != nil {
		return err
	}
	if retired {
		return ErrNodeRetired
	}
	var previous int64
	err = tx.QueryRow(ctx, `SELECT sample_sequence FROM node_traffic_delivery WHERE node_id=$1::uuid FOR UPDATE`, nodeID).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if delivery.Snapshot.Sequence <= previous {
		return tx.Commit(ctx)
	}
	at := delivery.RecordedAt.UTC()
	if at.After(time.Now().UTC()) {
		at = time.Now().UTC()
	}
	crossed, err := saveClientTraffic(ctx, tx, nodeID, delivery.Snapshot.Clients, at, delivery.Snapshot.Epoch, delivery.Snapshot.Sequence)
	if err != nil {
		return err
	}
	for _, clientID := range crossed {
		var credential string
		if err = tx.QueryRow(ctx, `SELECT vless_uuid::text FROM vpn_clients WHERE id=$1::uuid`, clientID).Scan(&credential); err != nil {
			return err
		}
		rebuilds, err := rebuildClientAccessNodes(ctx, tx, clientID, credential)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.traffic_quota_exceeded','system','traffic-accounting',jsonb_build_object('client_id',$2::text,'rebuild_count',$3::integer))`, tenant, clientID, rebuilds); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO node_traffic_delivery(node_id,sample_sequence,recorded_at) VALUES($1::uuid,$2,$3) ON CONFLICT(node_id) DO UPDATE SET sample_sequence=EXCLUDED.sample_sequence,recorded_at=EXCLUDED.recorded_at,received_at=now()`, nodeID, delivery.Snapshot.Sequence, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
