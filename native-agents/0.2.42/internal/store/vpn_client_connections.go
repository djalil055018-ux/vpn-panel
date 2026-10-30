package store

import (
	"context"
	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

func (p *Postgres) ListVPNClientConnections(
	ctx context.Context,
	clientID string,
) (
	[]model.VPNClientConnection,
	error,
) {
	client, err := p.GetVPNClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	branding, err := p.GetTenantBranding(ctx, client.TenantID)
	if err != nil {
		return nil, err
	}

	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	connections, err := listNativeVPNClientConnections(ctx, tx, clientID)
	if err != nil {
		return nil, err
	}
	imported, err := listImportedVPNClientConnections(ctx, tx, clientID)
	if err != nil {
		return nil, err
	}
	connections = append(connections, imported...)
	cascades, err := listCascadeVPNClientConnections(ctx, tx, clientID)
	if err != nil {
		return nil, err
	}
	connections = append(connections, cascades...)
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	wireguard, err := p.listWireGuardConnections(ctx, clientID)
	if err != nil {
		return nil, err
	}
	openvpn, err := p.listOpenVPNConnections(ctx, clientID)
	if err != nil {
		return nil, err
	}
	pptp, err := p.listPPTPConnections(ctx, clientID)
	if err != nil {
		return nil, err
	}
	connections = append(append(append(connections, wireguard...), openvpn...), pptp...)
	for i := range connections {
		connections[i].BrandName = branding.DisplayName
	}
	return connections, nil
}

func listNativeVPNClientConnections(ctx context.Context, tx pgx.Tx, clientID string) ([]model.VPNClientConnection, error) {
	rows, err :=
		tx.Query(
			ctx,
			`
			SELECT
				c.id::text,
				c.name,

				s.id::text,
				s.name,
				COALESCE(s.subscription_name,''),

				s.public_address,
				s.public_port,

				s.protocol,
				s.transport,
				s.security,
				n.runtime_core,

				CASE WHEN s.protocol='shadowsocks' THEN '' ELSE c.vless_uuid::text END,

				CASE WHEN s.security='tls' THEN cert.domain ELSE COALESCE(r.server_name,'') END,
				COALESCE(r.fingerprint, 'chrome'),
				COALESCE(r.short_id, ''),
				CASE WHEN s.protocol='shadowsocks' THEN ss.server_key || ':' || sck.client_key ELSE COALESCE(r.public_key, '') END

			FROM vpn_clients c

			JOIN vpn_effective_client_services cs
				ON cs.client_id = c.id
				AND cs.tenant_id = c.tenant_id

			JOIN vpn_services s
				ON s.id = cs.service_id
				AND s.tenant_id = cs.tenant_id

			JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id

			LEFT JOIN vpn_service_reality r
				ON r.service_id = s.id
				AND r.tenant_id = s.tenant_id

			LEFT JOIN vpn_service_tls tls ON tls.service_id=s.id AND tls.tenant_id=s.tenant_id AND tls.node_id=s.node_id
			LEFT JOIN vpn_service_shadowsocks ss ON ss.service_id=s.id AND ss.tenant_id=s.tenant_id
			LEFT JOIN vpn_client_shadowsocks_keys sck ON sck.client_id=c.id AND sck.tenant_id=c.tenant_id AND sck.credential_uuid=c.vless_uuid
			LEFT JOIN node_certificates cert ON cert.id=tls.certificate_id AND cert.node_id=s.node_id AND cert.tenant_id=s.tenant_id
			WHERE c.id = $1::uuid

			  AND c.status = 'active' AND NOT c.remnawave_hold

			  AND (
				c.expires_at IS NULL
				OR c.expires_at > now()
			  )

			  AND NOT vpn_client_quota_exceeded(c.id)

			  AND s.enabled = true
 AND NOT EXISTS (SELECT 1 FROM node_xray_profile_bindings b WHERE b.service_id=s.id AND b.tenant_id=s.tenant_id)
			  AND ((s.protocol IN ('vless','trojan') AND (s.transport='tcp' OR (s.transport IN ('xhttp','ws','grpc') AND s.protocol='vless' AND s.security='tls')))
			    OR (s.protocol='hysteria2' AND s.transport='udp' AND s.security='tls')
			    OR (s.protocol='shadowsocks' AND s.transport='tcp,udp' AND s.security='shadowsocks'))
			  AND s.security IN ('reality','tls','shadowsocks')

			  AND s.public_address IS NOT NULL
			  AND s.public_port IS NOT NULL

			  AND ((s.security='reality' AND r.public_key IS NOT NULL) OR (s.security='tls' AND cert.environment='production' AND cert.status IN ('active','renewing') AND cert.not_before<=now() AND cert.not_after>now()) OR (s.protocol='shadowsocks' AND ss.server_key IS NOT NULL AND sck.client_key IS NOT NULL))

			ORDER BY
				s.created_at ASC,
				s.id ASC
			`,
			clientID,
		)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	connections :=
		make(
			[]model.VPNClientConnection,
			0,
		)

	for rows.Next() {
		var connection model.VPNClientConnection

		if err :=
			rows.Scan(
				&connection.ClientID,
				&connection.ClientName,

				&connection.ServiceID,
				&connection.ServiceName,
				&connection.SubscriptionName,

				&connection.Address,
				&connection.Port,

				&connection.Protocol,
				&connection.Transport,
				&connection.Security,
				&connection.RuntimeCore,

				&connection.UUID,

				&connection.ServerName,
				&connection.Fingerprint,
				&connection.ShortID,
				&connection.Password,
			); err != nil {

			return nil, err
		}

		connections =
			append(
				connections,
				connection,
			)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}
