package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

var ErrSubscriptionName = errors.New("invalid subscription name")

// Only presentation metadata changes. In particular this method never queues
// a deployment, edits source bundles, or rotates connection credentials.
func (p *Postgres) SetVPNServiceSubscriptionName(ctx context.Context, serviceID, name string) (model.VPNService, error) {
	if !model.ValidSubscriptionName(name) {
		return model.VPNService{}, ErrSubscriptionName
	}
	name = strings.TrimSpace(name)
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.VPNService{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	err = tx.QueryRow(ctx, `SELECT s.tenant_id::text FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id WHERE s.id=$1::uuid AND n.status<>'retired' FOR UPDATE OF s`, serviceID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNService{}, ErrNotFound
	}
	if err != nil {
		return model.VPNService{}, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return model.VPNService{}, ErrNotFound
	}
	tag, err := tx.Exec(ctx, `UPDATE vpn_services SET subscription_name=NULLIF($2,''),updated_at=now() WHERE id=$1::uuid AND subscription_name IS DISTINCT FROM NULLIF($2,'')`, serviceID, name)
	if err != nil {
		return model.VPNService{}, err
	}
	if tag.RowsAffected() > 0 {
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_service.subscription_name_updated',$2,$3,jsonb_build_object('service_id',$4::text,'name',NULLIF($5::text,'')))`, tenant, actor, actorID, serviceID, name)
		if err != nil {
			return model.VPNService{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return model.VPNService{}, err
	}
	return p.GetVPNService(ctx, serviceID)
}

// Return the real fallback label for the editor, including the original imported
// remark. Never expose the rest of an imported bundle through service metadata.
func (p *Postgres) decorateVPNServiceNames(ctx context.Context, services []model.VPNService) error {
	brands := map[string]string{}
	ids := []string{}
	positions := map[string]int{}
	for i, s := range services {
		if !tenantScopeAllowed(ctx, s.TenantID) {
			return ErrNotFound
		}
		brand, ok := brands[s.TenantID]
		if !ok {
			b, err := p.GetTenantBranding(ctx, s.TenantID)
			if err != nil {
				return err
			}
			brand = b.DisplayName
			brands[s.TenantID] = brand
		}
		services[i].SubscriptionDefaultName = (model.VPNClientConnection{BrandName: brand, ServiceName: s.Name}).DisplayName()
		ids = append(ids, s.ID)
		positions[s.ID] = i
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := p.Pool.Query(ctx, `SELECT hs.service_id::text,hs.source_host_id::text,r.bundle_sha256,r.bundle
 FROM imported_subscription_host_services hs
 JOIN imported_subscription_profiles head ON head.revision_id=hs.revision_id AND head.tenant_id=hs.tenant_id
 JOIN imported_subscription_revisions r ON r.id=head.revision_id AND r.tenant_id=head.tenant_id
 WHERE hs.service_id=ANY($1::uuid[]) AND head.state='active'`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, hostID, digest string
		var raw []byte
		if err = rows.Scan(&id, &hostID, &digest, &raw); err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		var bundle ImportedSubscriptionBundle
		if hex.EncodeToString(sum[:]) != digest || json.Unmarshal(raw, &bundle) != nil || bundle.Version != 1 {
			return ErrImportedSubscriptionIdentity
		}
		found := false
		for _, bound := range bundle.Hosts.Hosts {
			if bound.SourceHostID != hostID {
				continue
			}
			for _, serviceID := range bound.ServiceIDs {
				if serviceID == id {
					services[positions[id]].SubscriptionDefaultName = bound.Host.Name
					found = true
				}
			}
		}
		if !found {
			return ErrImportedSubscriptionIdentity
		}
	}
	return rows.Err()
}
