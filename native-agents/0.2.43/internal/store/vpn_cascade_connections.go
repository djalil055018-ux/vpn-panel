package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
	"vpn-platform/internal/xrayprofile"
)

// Publish only after both current node generations are healthy. The client
// receives its own credential and the entry identity, never the transit user.
func listCascadeVPNClientConnections(ctx context.Context, tx pgx.Tx, clientID string) ([]model.VPNClientConnection, error) {
	rows, err := tx.Query(ctx, `SELECT c.tenant_id::text,c.id::text,c.name,c.vless_uuid::text,k.id::text,k.name,k.entry_node_id::text,k.entry_service_id::text,k.entry_port,s.public_address,r.server_name,r.fingerprint,r.short_id,r.public_key,COALESCE(n.agent_version,''),COALESCE(x.agent_version,'')
 FROM vpn_effective_client_cascades e JOIN vpn_clients c ON c.id=e.client_id AND c.tenant_id=e.tenant_id
 JOIN vpn_active_cascades k ON k.id=e.cascade_id AND k.tenant_id=e.tenant_id
 JOIN vpn_services s ON s.id=k.entry_service_id AND s.tenant_id=k.tenant_id
 JOIN vpn_service_reality r ON r.service_id=s.id AND r.tenant_id=s.tenant_id
 JOIN nodes n ON n.id=k.entry_node_id AND n.tenant_id=k.tenant_id
 JOIN nodes x ON x.id=k.exit_node_id AND x.tenant_id=k.tenant_id
 JOIN deployments nd ON nd.node_id=n.id AND nd.generation=n.desired_generation
 JOIN deployments xd ON xd.node_id=x.id AND xd.generation=x.desired_generation
 JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation
 WHERE c.id=$1::uuid AND n.applied_generation=n.desired_generation AND x.applied_generation=x.desired_generation
 AND nd.status='healthy' AND xd.status='healthy' AND s.public_address IS NOT NULL AND r.public_key IS NOT NULL
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(ds.document->'xray_cascades'->'entries','[]'::jsonb)) ce,
 jsonb_array_elements(COALESCE(ce->'clients','[]'::jsonb)) u WHERE ce->>'id'=k.id::text AND u->>'stats_key'=c.id::text AND u->>'id'=c.vless_uuid::text)
 ORDER BY k.created_at,k.id`, clientID)
	if err != nil {
		return nil, err
	}
	type pending struct {
		connection    model.VPNClientConnection
		node, service string
	}
	items := []pending{}
	for rows.Next() {
		c := model.VPNClientConnection{RuntimeCore: "xray", Protocol: "vless", Transport: "tcp", Security: "reality"}
		var tenant, node, service, entryAgent, exitAgent string
		if err = rows.Scan(&tenant, &c.ClientID, &c.ClientName, &c.UUID, &c.ServiceID, &c.ServiceName, &node, &service, &c.Port, &c.Address, &c.ServerName, &c.Fingerprint, &c.ShortID, &c.Password, &entryAgent, &exitAgent); err != nil {
			rows.Close()
			return nil, err
		}
		if !tenantScopeAllowed(ctx, tenant) {
			rows.Close()
			return nil, ErrNotFound
		}
		if !model.XrayCascadeAgentCompatible(entryAgent) || !model.XrayCascadeAgentCompatible(exitAgent) {
			continue
		}
		c.SubscriptionName = c.ServiceName
		items = append(items, pending{c, node, service})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []model.VPNClientConnection{}
	for _, item := range items {
		c := item.connection
		flow := ""
		profile, status, _, err := registeredXrayProfile(ctx, tx, item.node)
		if err != nil {
			return nil, err
		}
		if profile != nil {
			if status != "active" {
				continue
			}
			flow, err = xrayprofile.VLESSFlow(profile, item.service)
			if err != nil {
				return nil, ErrVPNCascadeIdentity
			}
		}
		h := subscriptioncompat.Host{Name: c.ServiceName, Address: c.Address, Port: c.Port, Protocol: "vless", Transport: "tcp", Security: "reality", ProtocolOptions: subscriptioncompat.Options{"encryption": "none", "flow": flow}, TransportOptions: subscriptioncompat.Options{}, SecurityOptions: subscriptioncompat.Options{"serverName": c.ServerName, "fingerprint": c.Fingerprint, "shortId": c.ShortID, "publicKey": c.Password}}
		if _, err = subscriptioncompat.ShareURI(h, c.UUID); err != nil {
			return nil, ErrVPNCascadeIdentity
		}
		c.ImportedProfile, err = json.Marshal(h)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
