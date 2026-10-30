package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

var ErrPPTPCapacity = errors.New("PPTP service has no free client addresses (252 bindings maximum)")

// Rotate one PPTP credential without changing credentials of other protocols.
// The key and its replacement desired generation commit in one transaction.
func (p *Postgres) RotatePPTPClientCredential(ctx context.Context, serviceID, clientID string) (model.DesiredState, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.DesiredState{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant, node string
	err = tx.QueryRow(ctx, `SELECT s.tenant_id::text,s.node_id::text FROM vpn_services s JOIN vpn_client_pptp k ON k.service_id=s.id AND k.tenant_id=s.tenant_id JOIN nodes n ON n.id=s.node_id AND n.runtime_core='pptp' WHERE s.id=$1::uuid AND k.client_id=$2::uuid AND s.protocol='pptp'`, serviceID, clientID).Scan(&tenant, &node)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, ErrNotFound
	}
	if err != nil {
		return model.DesiredState{}, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return model.DesiredState{}, ErrNotFound
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return model.DesiredState{}, err
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM nodes WHERE id=$1::uuid FOR UPDATE`, node); err != nil {
		return model.DesiredState{}, err
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return model.DesiredState{}, err
	}
	tag, err := tx.Exec(ctx, `UPDATE vpn_client_pptp SET password=$3 WHERE service_id=$1::uuid AND client_id=$2::uuid AND tenant_id=$4::uuid`, serviceID, clientID, hex.EncodeToString(secret), tenant)
	if err != nil {
		return model.DesiredState{}, err
	}
	if tag.RowsAffected() != 1 {
		return model.DesiredState{}, ErrNotFound
	}
	state, release, err := buildNodeDesiredStateTx(ctx, tx, node)
	if err != nil {
		return model.DesiredState{}, err
	}
	if err = saveDesiredStateTx(ctx, tx, node, state, release); err != nil {
		return model.DesiredState{}, err
	}
	actorType, actorID := accessActor(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'pptp.credential_rotated',$2,$3,jsonb_build_object('service_id',$4::text,'client_id',$5::text,'generation',$6::bigint))`, tenant, actorType, actorID, serviceID, clientID, state.Generation); err != nil {
		return model.DesiredState{}, err
	}
	return state, tx.Commit(ctx)
}

// The caller holds the node lock, serializing allocation with every rebuild.
// Rotating the common client credential rotates PPTP's independently generated
// password as well. Rebuilding an unchanged client preserves its password/IP.
func fillPPTPKeysTx(ctx context.Context, tx pgx.Tx, services []model.ServiceSpec) error {
	for i := range services {
		s := &services[i]
		if s.Protocol != "pptp" {
			continue
		}
		for j := range s.Clients {
			c := &s.Clients[j]
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return err
			}
			var peer model.PPTPPeer
			var index int
			err := tx.QueryRow(ctx, `INSERT INTO vpn_client_pptp(service_id,client_id,tenant_id,credential_uuid,password,address_index)
    SELECT s.id,c.id,c.tenant_id,c.vless_uuid,$4,COALESCE(
      (SELECT address_index FROM vpn_client_pptp WHERE service_id=s.id AND client_id=c.id),
      (SELECT min(x) FROM generate_series(2,253) pool(x) WHERE NOT EXISTS(SELECT 1 FROM vpn_client_pptp k WHERE k.service_id=s.id AND k.address_index=x)))
    FROM vpn_clients c JOIN vpn_services s ON s.tenant_id=c.tenant_id
    WHERE s.id=$1::uuid AND c.id=$2::uuid AND c.vless_uuid=$3::uuid AND s.protocol='pptp'
    ON CONFLICT(service_id,client_id) DO UPDATE SET
    password=CASE WHEN vpn_client_pptp.credential_uuid=EXCLUDED.credential_uuid THEN vpn_client_pptp.password ELSE EXCLUDED.password END,
    credential_uuid=EXCLUDED.credential_uuid RETURNING password,address_index`, s.ID, c.StatsKey, c.ID, hex.EncodeToString(raw)).Scan(&peer.Password, &index)
			if err != nil {
				var pgerr *pgconn.PgError
				if errors.As(err, &pgerr) && pgerr.Code == "23502" && pgerr.ColumnName == "address_index" {
					return ErrPPTPCapacity
				}
				return err
			}
			peer.Address = fmt.Sprintf("10.78.0.%d", index)
			c.PPTP = &peer
			c.ID = c.StatsKey
		}
	}
	return nil
}

func (p *Postgres) listPPTPConnections(ctx context.Context, clientID string) ([]model.VPNClientConnection, error) {
	rows, err := p.Pool.Query(ctx, `SELECT c.id::text,c.name,s.id::text,s.name,COALESCE(s.subscription_name,''),s.public_address,s.public_port,k.password
  FROM vpn_clients c JOIN vpn_effective_client_services cs ON cs.client_id=c.id AND cs.tenant_id=c.tenant_id
  JOIN vpn_services s ON s.id=cs.service_id AND s.tenant_id=cs.tenant_id
  JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id AND n.runtime_core='pptp'
  JOIN vpn_client_pptp k ON k.service_id=s.id AND k.client_id=c.id AND k.tenant_id=c.tenant_id AND k.credential_uuid=c.vless_uuid
  WHERE c.id=$1::uuid AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now())
  AND s.enabled AND s.protocol='pptp' AND s.transport='tcp,gre' AND s.security='mppe' AND s.port=1723 AND s.public_address IS NOT NULL AND s.public_port=1723
  AND NOT vpn_client_quota_exceeded(c.id)
  ORDER BY s.created_at,s.id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.VPNClientConnection{}
	for rows.Next() {
		c := model.VPNClientConnection{RuntimeCore: "pptp", Protocol: "pptp", Transport: "tcp,gre", Security: "mppe"}
		if err = rows.Scan(&c.ClientID, &c.ClientName, &c.ServiceID, &c.ServiceName, &c.SubscriptionName, &c.Address, &c.Port, &c.Password); err != nil {
			return nil, err
		}
		c.Username = c.ClientID
		c.Config, err = compiler.PPTPProfile(c.Address, c.Username, c.Password)
		if err != nil {
			return nil, err
		}
		c.ConfigFilename = "vpn-" + c.ServiceID[:8] + ".pptp.txt"
		result = append(result, c)
	}
	return result, rows.Err()
}
