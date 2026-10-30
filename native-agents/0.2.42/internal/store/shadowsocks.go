package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

func newShadowsocksKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// Keys are generated inside the same transaction as access and desired state.
// The credential UUID binds rotation to the existing all-protocol reset flow.
func fillShadowsocksKeysTx(ctx context.Context, tx pgx.Tx, services []model.ServiceSpec) error {
	for i := range services {
		s := &services[i]
		if s.Protocol != "shadowsocks" {
			continue
		}
		key, err := newShadowsocksKey()
		if err != nil {
			return err
		}
		var serverKey string
		err = tx.QueryRow(ctx, `INSERT INTO vpn_service_shadowsocks(service_id,tenant_id,server_key) SELECT id,tenant_id,$2 FROM vpn_services WHERE id=$1::uuid ON CONFLICT(service_id) DO UPDATE SET server_key=vpn_service_shadowsocks.server_key RETURNING server_key`, s.ID, key).Scan(&serverKey)
		if err != nil {
			return err
		}
		s.Shadowsocks = &model.ShadowsocksSpec{Method: model.ShadowsocksMethod, ServerKey: serverKey}
		for j := range s.Clients {
			c := &s.Clients[j]
			key, err = newShadowsocksKey()
			if err != nil {
				return err
			}
			var clientKey string
			err = tx.QueryRow(ctx, `INSERT INTO vpn_client_shadowsocks_keys(client_id,tenant_id,credential_uuid,client_key) SELECT id,tenant_id,vless_uuid,$3 FROM vpn_clients WHERE id=$1::uuid AND vless_uuid=$2::uuid ON CONFLICT(client_id,credential_uuid) DO UPDATE SET client_key=vpn_client_shadowsocks_keys.client_key RETURNING client_key`, c.StatsKey, c.ID, key).Scan(&clientKey)
			if err != nil {
				return err
			}
			c.ID = clientKey
		}
	}
	return nil
}

func validateShadowsocksDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState) error {
	for _, s := range state.Services {
		if s.Protocol != "shadowsocks" {
			continue
		}
		if state.Core.Type != "xray" || s.Transport != "tcp,udp" || s.Security != "shadowsocks" || s.Shadowsocks == nil || s.Shadowsocks.Method != model.ShadowsocksMethod || !model.ValidShadowsocksKey(s.Shadowsocks.ServerKey) {
			return errors.New("Shadowsocks requires Xray, native TCP/UDP and AEAD-2022 keys")
		}
		var compatible bool
		if err := tx.QueryRow(ctx, `SELECT CASE WHEN agent_version ~ '^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$' THEN string_to_array(agent_version,'.')::int[] >= ARRAY[0,2,26] ELSE false END FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&compatible); err != nil {
			return err
		}
		if !compatible {
			return errors.New("Shadowsocks requires Agent 0.2.26 or newer")
		}
		for _, c := range s.Clients {
			if !model.ValidShadowsocksKey(c.ID) || c.ID == s.Shadowsocks.ServerKey {
				return errors.New("invalid Shadowsocks client key")
			}
		}
	}
	return nil
}
