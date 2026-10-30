package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

var ErrClientDeleteConfirmation = errors.New("client identity confirmation does not match")
var ErrImportedClientDeleteOwner = errors.New("owner role required to delete an imported client")

type VPNClientDeletion struct {
	ClientID          string                    `json:"client_id"`
	Deleted           bool                      `json:"deleted"`
	Rebuilds          []model.NodeRebuildResult `json:"rebuilds"`
	VoidedInvoices    int64                     `json:"voided_invoices"`
	PreservedInvoices int64                     `json:"preserved_invoices"`
	PreservedImport   bool                      `json:"preserved_import"`
}

// DeleteVPNClient removes the live account and credentials in the same
// transaction that removes it from every affected node's desired state.
// Applying those generations on connected nodes remains asynchronous.
func (p *Postgres) DeleteVPNClient(ctx context.Context, id, confirmedName string) (VPNClientDeletion, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return VPNClientDeletion{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	out, err := deleteVPNClientTx(ctx, tx, id, confirmedName)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

// The bot ledger calls the same lifecycle inside its receipt transaction.
func deleteVPNClientTx(ctx context.Context, tx pgx.Tx, id, confirmedName string) (VPNClientDeletion, error) {
	out := VPNClientDeletion{ClientID: id, Rebuilds: []model.NodeRebuildResult{}}
	var tenant string
	err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return out, ErrNotFound
	}
	// Removing a client only releases quota; no resource-row lock is needed.
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	client, err := scanVPNClient(tx.QueryRow(ctx, `SELECT `+vpnClientColumns+` FROM vpn_clients WHERE id=$1::uuid FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if client.Name != confirmedName {
		return out, ErrClientDeleteConfirmation
	}
	if client.RemnawaveHold && !remnawaveOwnerAllowed(ctx) {
		return out, ErrImportedClientDeleteOwner
	}
	// Include stale direct desired grants even if membership was already removed.
	// Native runtimes use the stable client ID; Xray uses the VLESS credential.
	rows, err := tx.Query(ctx, `SELECT n.id::text FROM nodes n WHERE n.tenant_id=$1::uuid AND n.status<>'retired' AND (vpn_node_cascade_client(n.id,$2::uuid,$3::text) OR
 EXISTS(SELECT 1 FROM vpn_effective_client_services e JOIN vpn_services s ON s.id=e.service_id AND s.tenant_id=e.tenant_id WHERE e.client_id=$2::uuid AND s.node_id=n.id AND s.enabled)
 OR EXISTS(SELECT 1 FROM desired_states ds,jsonb_array_elements(COALESCE(ds.document->'services','[]'::jsonb)) service,jsonb_array_elements(COALESCE(service->'clients','[]'::jsonb)) member
 WHERE ds.node_id=n.id AND ds.generation=n.desired_generation AND (member->>'stats_key'=$2::text OR member->>'id' IN ($2::text,$3::text)))) ORDER BY n.id`, tenant, id, client.VLESSUUID)
	if err != nil {
		return out, err
	}
	nodes := []string{}
	for rows.Next() {
		var node string
		if err = rows.Scan(&node); err != nil {
			rows.Close()
			return out, err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE status='pending') FROM billing_invoices WHERE client_id=$1::uuid AND tenant_id=$2::uuid`, id, tenant).Scan(&out.PreservedInvoices, &out.VoidedInvoices); err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_invoices SET deleted_client_id=client_id,status=CASE WHEN status='pending' THEN 'void' ELSE status END WHERE client_id=$1::uuid AND tenant_id=$2::uuid`, id, tenant)
	if err != nil {
		return out, err
	}
	tag, err := tx.Exec(ctx, `UPDATE remnawave_import_clients SET deleted_client_id=client_id,client_id=NULL,deleted_client_name=$2,deleted_at=now() WHERE client_id=$1::uuid`, id, client.Name)
	if err != nil {
		return out, err
	}
	out.PreservedImport = tag.RowsAffected() > 0
	if _, err = tx.Exec(ctx, `DELETE FROM vpn_clients WHERE id=$1::uuid AND tenant_id=$2::uuid`, id, tenant); err != nil {
		return out, err
	}
	for _, node := range nodes {
		state, release, e := buildNodeDesiredStateTx(ctx, tx, node)
		if e != nil {
			return out, e
		}
		if e = saveDesiredStateTx(ctx, tx, node, state, release); e != nil {
			return out, e
		}
		out.Rebuilds = append(out.Rebuilds, model.NodeRebuildResult{NodeID: node, Generation: state.Generation})
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.deleted',$2,$3,jsonb_build_object('client_id',$4::text,'rebuild_count',$5::integer,'preserved_invoices',$6::bigint,'voided_invoices',$7::bigint,'preserved_import',$8::boolean))`, tenant, actorType, actorID, id, len(nodes), out.PreservedInvoices, out.VoidedInvoices, out.PreservedImport)
	if err != nil {
		return out, err
	}
	out.Deleted = true
	return out, nil
}
