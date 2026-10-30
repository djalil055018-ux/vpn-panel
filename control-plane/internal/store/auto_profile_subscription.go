package store

import (
	"context"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

// The caller supplies connection indices from this same authorized snapshot.
// Cascades are omitted: their virtual IDs are not physical vpn_services, and
// an entry node being healthy alone cannot establish the exit node's health.
func readSubscriptionAuto(ctx context.Context, tx pgx.Tx, tenant, clientID string, services []string) (subscriptioncompat.AutoProfile, error) {
	settings, err := readAutoProfileSettings(ctx, tx, tenant)
	if err != nil {
		return subscriptioncompat.AutoProfile{}, err
	}
	result := subscriptioncompat.AutoProfile{Enabled: settings.Enabled, Name: settings.Name, RussiaDirect: settings.RussiaDirect, ClientKey: clientID}
	if !settings.Enabled || len(services) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `SELECT s.id::text,n.id::text
 FROM vpn_clients c
 JOIN vpn_effective_client_services cs ON cs.client_id=c.id AND cs.tenant_id=c.tenant_id
 JOIN vpn_services s ON s.id=cs.service_id AND s.tenant_id=cs.tenant_id
 JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
 JOIN node_health h ON h.node_id=n.id
 WHERE c.id=$1::uuid AND c.tenant_id=$2::uuid AND s.id=ANY($3::uuid[])
 AND c.status='active' AND NOT c.remnawave_hold AND (c.expires_at IS NULL OR c.expires_at>now()) AND NOT vpn_client_quota_exceeded(c.id)
 AND s.enabled AND n.status<>'retired' AND n.agent_token_hash IS NOT NULL
 AND n.last_seen_at>=now()-interval '2 minutes' AND h.checked_at>=now()-interval '2 minutes' AND h.healthy
 AND n.desired_generation=n.applied_generation AND h.applied_generation=n.applied_generation
 AND NOT EXISTS(SELECT 1 FROM deployments d WHERE d.node_id=n.id AND d.generation>=n.applied_generation AND d.status IN ('pending','applying'))
 AND NOT EXISTS(SELECT 1 FROM deployment_execution_leases l WHERE l.node_id=n.id AND l.state='active')
 AND NOT EXISTS(SELECT 1 FROM recovery_attempts r LEFT JOIN deployments d ON d.id=r.deployment_id
 WHERE r.node_id=n.id AND (r.status IN ('planned','approved') OR (r.status='executed' AND d.generation>=n.applied_generation AND d.status IN ('pending','applying'))))`, clientID, tenant, services)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	eligible := map[string]string{}
	for rows.Next() {
		var service, node string
		if err = rows.Scan(&service, &node); err != nil {
			return result, err
		}
		eligible[service] = node
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	for i, service := range services {
		if node, ok := eligible[service]; ok {
			result.Candidates = append(result.Candidates, subscriptioncompat.AutoCandidate{HostIndex: i, NodeID: node, ServiceID: service})
		}
	}
	return result, nil
}

func (p *Postgres) SubscriptionAutoForConnections(ctx context.Context, tenant, client string, connections []model.VPNClientConnection) (subscriptioncompat.AutoProfile, error) {
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return subscriptioncompat.AutoProfile{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	services := make([]string, len(connections))
	for i, c := range connections {
		services[i] = c.ServiceID
	}
	result, err := readSubscriptionAuto(ctx, tx, tenant, client, services)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func SubscriptionHost(c model.VPNClientConnection) (subscriptioncompat.Host, error) {
	if len(c.ImportedProfile) > 0 {
		return subscriptioncompat.DecodeHost(c.ImportedProfile)
	}
	return nativeSubscriptionHost(c, c.BrandName)
}
