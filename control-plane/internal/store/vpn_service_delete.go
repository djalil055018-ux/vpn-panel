package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrVPNServiceDeleteProtected = errors.New("vpn service is referenced by an immutable import or cascade")

type VPNServiceDeletion struct {
	ServiceID       string `json:"service_id"`
	NodeID          string `json:"node_id"`
	Deleted         bool   `json:"deleted"`
	Generation      int64  `json:"generation"`
	AffectedClients int64  `json:"affected_clients"`
	AffectedPlans   int64  `json:"affected_plans"`
}

// DeleteVPNServiceAndRebuild removes a protocol configuration and its direct
// client/plan grants in the same transaction that publishes a desired state
// without the listener. Immutable imported profiles and cascade endpoints must
// be removed through their own lifecycle first.
func (p *Postgres) DeleteVPNServiceAndRebuild(ctx context.Context, serviceID, confirmedName string) (VPNServiceDeletion, error) {
	out := VPNServiceDeletion{ServiceID: serviceID}
	if !adminOwnerAllowed(ctx) {
		return out, ErrAdminPermission
	}

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	var tenantID string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM vpn_services WHERE id=$1::uuid`, serviceID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenantID); err != nil {
		return out, err
	}

	var name, nodeID, nodeStatus string
	err = tx.QueryRow(ctx, `SELECT s.name,s.node_id::text,n.status FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id WHERE s.id=$1::uuid FOR UPDATE OF s,n`, serviceID).Scan(&name, &nodeID, &nodeStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if name != confirmedName {
		return out, ErrVPNServiceDeleteConfirmation
	}
	if nodeStatus == "retired" {
		return out, ErrNodeRetired
	}

	var protected bool
	err = tx.QueryRow(ctx, `SELECT
  EXISTS(SELECT 1 FROM vpn_cascades WHERE entry_service_id=$1::uuid OR exit_service_id=$1::uuid)
  OR EXISTS(SELECT 1 FROM node_xray_profile_bindings WHERE service_id=$1::uuid)
  OR EXISTS(SELECT 1 FROM imported_subscription_host_services WHERE service_id=$1::uuid)
  OR EXISTS(SELECT 1 FROM imported_subscription_squad_services WHERE service_id=$1::uuid)`, serviceID).Scan(&protected)
	if err != nil {
		return out, err
	}
	if protected {
		return out, ErrVPNServiceDeleteProtected
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM vpn_effective_client_services WHERE service_id=$1::uuid`, serviceID).Scan(&out.AffectedClients); err != nil {
		return out, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM vpn_access_plan_services WHERE service_id=$1::uuid`, serviceID).Scan(&out.AffectedPlans); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM vpn_services WHERE id=$1::uuid`, serviceID); err != nil {
		return out, err
	}

	state, coreReleaseID, err := buildNodeDesiredStateTx(ctx, tx, nodeID)
	if err != nil {
		return out, err
	}
	if err = saveDesiredStateTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return out, err
	}
	actorType, actorID := accessActor(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'vpn_service.deleted',$3,$4,jsonb_build_object('service_id',$5::text,'service_name',$6::text,'affected_clients',$7::bigint,'affected_plans',$8::bigint,'generation',$9::bigint))`, tenantID, nodeID, actorType, actorID, serviceID, name, out.AffectedClients, out.AffectedPlans, state.Generation); err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	out.NodeID = nodeID
	out.Generation = state.Generation
	out.Deleted = true
	return out, nil
}

var ErrVPNServiceDeleteConfirmation = errors.New("exact service name confirmation required")
