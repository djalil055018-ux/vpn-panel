package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"strings"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func wireGuardAddress(index int) string { return fmt.Sprintf("10.66.%d.%d/32", index/256, index%256) }

// buildNodeDesiredStateTx holds the node lock, serializing address allocation.
func fillWireGuardKeysTx(ctx context.Context, tx pgx.Tx, services []model.ServiceSpec) error {
	for i := range services {
		s := &services[i]
		if s.Protocol != "wireguard" && s.Protocol != "amneziawg" {
			continue
		}
		key, err := newShadowsocksKey()
		if err != nil {
			return err
		}
		public, err := model.WireGuardPublicKey(key)
		if err != nil {
			return err
		}
		var private string
		err = tx.QueryRow(ctx, `INSERT INTO vpn_service_wireguard(service_id,tenant_id,private_key,public_key) SELECT id,tenant_id,$2,$3 FROM vpn_services WHERE id=$1::uuid ON CONFLICT(service_id) DO UPDATE SET private_key=vpn_service_wireguard.private_key RETURNING private_key`, s.ID, key, public).Scan(&private)
		if err != nil {
			return err
		}
		s.WireGuard = &model.WireGuardSpec{PrivateKey: private}
		for j := range s.Clients {
			c := &s.Clients[j]
			key, err = newShadowsocksKey()
			if err != nil {
				return err
			}
			public, err = model.WireGuardPublicKey(key)
			if err != nil {
				return err
			}
			psk, err := newShadowsocksKey()
			if err != nil {
				return err
			}
			var index int
			var peer model.WireGuardPeer
			err = tx.QueryRow(ctx, `INSERT INTO vpn_client_wireguard(service_id,client_id,tenant_id,credential_uuid,private_key,public_key,preshared_key,address_index)
			 SELECT s.id,c.id,c.tenant_id,c.vless_uuid,$4,$5,$6,COALESCE((SELECT address_index FROM vpn_client_wireguard WHERE service_id=s.id AND client_id=c.id),(SELECT COALESCE(MAX(address_index),1)+1 FROM vpn_client_wireguard WHERE service_id=s.id))
			 FROM vpn_clients c JOIN vpn_services s ON s.tenant_id=c.tenant_id WHERE s.id=$1::uuid AND c.id=$2::uuid AND c.vless_uuid=$3::uuid
			 ON CONFLICT(service_id,client_id) DO UPDATE SET
			 private_key=CASE WHEN vpn_client_wireguard.credential_uuid=EXCLUDED.credential_uuid THEN vpn_client_wireguard.private_key ELSE EXCLUDED.private_key END,
			 public_key=CASE WHEN vpn_client_wireguard.credential_uuid=EXCLUDED.credential_uuid THEN vpn_client_wireguard.public_key ELSE EXCLUDED.public_key END,
			 preshared_key=CASE WHEN vpn_client_wireguard.credential_uuid=EXCLUDED.credential_uuid THEN vpn_client_wireguard.preshared_key ELSE EXCLUDED.preshared_key END,
			 credential_uuid=EXCLUDED.credential_uuid RETURNING public_key,preshared_key,address_index`, s.ID, c.StatsKey, c.ID, key, public, psk).Scan(&peer.PublicKey, &peer.PresharedKey, &index)
			if err != nil {
				return err
			}
			peer.Address = wireGuardAddress(index)
			c.WireGuard = &peer
			c.ID = c.StatsKey
		}
	}
	return nil
}

func validateWireGuardDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState) error {
	for _, s := range state.Services {
		if s.Protocol == "amneziawg" {
			if state.Core.Type != "amneziawg" {
				return ErrNodeRuntime
			}
			if _, err := compiler.CompileAmneziaWG(s); err != nil {
				return err
			}
			continue
		}
		if s.Protocol != "wireguard" {
			continue
		}
		if state.Core.Type == "wireguard" {
			if _, err := compiler.CompileKernelWireGuard(s); err != nil {
				return err
			}
			continue
		}
		if state.Core.Type != "xray" {
			return errors.New("WireGuard requires Xray")
		}
		var compatible bool
		if err := tx.QueryRow(ctx, `SELECT CASE WHEN agent_version ~ '^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$' THEN string_to_array(agent_version,'.')::int[]>=ARRAY[0,2,26] ELSE false END FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&compatible); err != nil {
			return err
		}
		if !compatible {
			return errors.New("WireGuard requires Agent 0.2.26 or newer")
		}
		if _, err := compiler.CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}}); err != nil {
			return err
		}
	}
	return nil
}

func (p *Postgres) listWireGuardConnections(ctx context.Context, clientID string) ([]model.VPNClientConnection, error) {
	rows, err := p.Pool.Query(ctx, `SELECT c.id::text,c.name,s.id::text,s.name,COALESCE(s.subscription_name,''),s.public_address,s.public_port,k.private_key,w.public_key,k.preshared_key,k.address_index,n.runtime_core,s.protocol,COALESCE(a.version,''),COALESCE(a.settings,'{}'::jsonb)
	 FROM vpn_clients c JOIN vpn_effective_client_services cs ON cs.client_id=c.id AND cs.tenant_id=c.tenant_id
	 JOIN vpn_services s ON s.id=cs.service_id AND s.tenant_id=cs.tenant_id
	 JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
	 JOIN vpn_service_wireguard w ON w.service_id=s.id AND w.tenant_id=s.tenant_id
	 JOIN vpn_client_wireguard k ON k.service_id=s.id AND k.client_id=c.id AND k.tenant_id=c.tenant_id AND k.credential_uuid=c.vless_uuid
	 LEFT JOIN vpn_service_amneziawg a ON a.service_id=s.id AND a.tenant_id=s.tenant_id
	 WHERE c.id=$1::uuid AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now()) AND s.enabled
	 AND ((s.protocol='wireguard' AND s.security='wireguard') OR (s.protocol='amneziawg' AND s.security='amneziawg' AND n.runtime_core='amneziawg' AND a.service_id IS NOT NULL))
	 AND s.transport='udp' AND s.public_address IS NOT NULL AND s.public_port IS NOT NULL
	 AND NOT vpn_client_quota_exceeded(c.id)
	 ORDER BY s.created_at,s.id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.VPNClientConnection{}
	for rows.Next() {
		c := model.VPNClientConnection{Protocol: "wireguard", Transport: "udp", Security: "wireguard"}
		var private, public, psk string
		var settings []byte
		var index int
		if err := rows.Scan(&c.ClientID, &c.ClientName, &c.ServiceID, &c.ServiceName, &c.SubscriptionName, &c.Address, &c.Port, &private, &public, &psk, &index, &c.RuntimeCore, &c.Protocol, &c.AmneziaWGVersion, &settings); err != nil {
			return nil, err
		}
		if c.Protocol == "amneziawg" {
			var spec model.AmneziaWGSpec
			if json.Unmarshal(settings, &spec) != nil || spec.Version != c.AmneziaWGVersion {
				return nil, ErrAmneziaWGConfiguration
			}
			c.Security = "amneziawg"
			c.Config, err = compiler.AmneziaWGProfile(private, public, psk, wireGuardAddress(index), c.Address, c.Port, spec)
		} else {
			c.Config, err = compiler.WireGuardProfile(private, public, psk, wireGuardAddress(index), c.Address, c.Port)
		}
		if err != nil {
			return nil, err
		}
		c.ConfigFilename = "vpn-" + c.ServiceID[:8] + ".conf"
		if c.Protocol == "amneziawg" {
			c.ConfigFilename = "amneziawg-" + strings.ReplaceAll(c.AmneziaWGVersion, ".", "-") + "-" + c.ServiceID[:8] + ".conf"
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
