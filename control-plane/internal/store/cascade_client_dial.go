package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

// Performance metadata never supplies a credential or grants a service. The
// caller has already selected the exact authorized hosts and service identities.
func applyClientCascadeDialTx(ctx context.Context, tx pgx.Tx, tenant string, hosts []subscriptioncompat.Host, services []string) ([]subscriptioncompat.Host, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return nil, ErrNotFound
	}
	if len(hosts) != len(services) {
		return nil, ErrVPNCascade
	}
	if len(hosts) == 0 {
		return hosts, nil
	}
	rows, err := tx.Query(ctx, `SELECT s.id::text,s.public_address,c.connect_race_ip,c.connect_race_attempts
 FROM vpn_active_cascades c JOIN vpn_services e ON e.id=c.exit_service_id AND e.tenant_id=c.tenant_id
 JOIN vpn_services s ON s.node_id=c.exit_node_id AND s.tenant_id=c.tenant_id AND s.public_address=e.public_address
 WHERE c.tenant_id=$1::uuid AND c.connect_race_clients AND c.connect_race_attempts>0
 AND s.id=ANY($2::uuid[]) AND s.enabled AND s.protocol IN ('vless','trojan')
 AND s.security IN ('tls','reality') AND s.transport IN ('tcp','ws','grpc','xhttp') ORDER BY c.id,s.id`, tenant, services)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type policy struct {
		address, ip string
		attempts    int
	}
	policies := map[string]policy{}
	for rows.Next() {
		var id string
		var v policy
		if err = rows.Scan(&id, &v.address, &v.ip, &v.attempts); err != nil {
			return nil, err
		}
		if !model.ValidCascadeDial(v.ip, v.attempts) {
			return nil, ErrVPNCascade
		}
		if prior, ok := policies[id]; ok && prior != v {
			return nil, ErrVPNCascade
		}
		policies[id] = v
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	result := append([]subscriptioncompat.Host(nil), hosts...)
	for i, id := range services {
		v, ok := policies[id]
		if !ok || result[i].Address != v.address {
			continue
		}
		if (result[i].Protocol != "vless" && result[i].Protocol != "trojan") || (result[i].Security != "tls" && result[i].Security != "reality") {
			continue
		}
		if value, ok := result[i].Stream.Sockopt["dialerProxy"].(string); ok && value != "" {
			continue
		}
		switch result[i].Transport {
		case "tcp", "ws", "grpc", "xhttp":
		default:
			continue
		}
		result[i].ConnectRaceIP, result[i].ConnectRaceAttempts = v.ip, v.attempts
	}
	return result, nil
}

func (p *Postgres) ApplyClientCascadeDial(ctx context.Context, tenant string, hosts []subscriptioncompat.Host, services []string) ([]subscriptioncompat.Host, error) {
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	result, err := applyClientCascadeDialTx(ctx, tx, tenant, hosts, services)
	if err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}
