package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

// A published transport belongs to its service, not only to the accounts that
// happened to exist during import. Current effective grants select the hosts.
// Both subscription paths use the current native credential and the same
// repeatable-read view as the native connections query.
func listImportedVPNClientConnections(ctx context.Context, tx pgx.Tx, clientID string) ([]model.VPNClientConnection, error) {
	rows, err := tx.Query(ctx, `SELECT c.tenant_id::text,c.id::text,c.name,c.vless_uuid::text,
 r.id::text,r.bundle_sha256,r.bundle,r.inventory_sha256,hs.source_host_id::text,
 s.id::text,s.name,COALESCE(s.subscription_name,''),s.protocol,s.transport,s.security,n.runtime_core
 FROM vpn_clients c
 JOIN vpn_effective_client_services e ON e.client_id=c.id AND e.tenant_id=c.tenant_id
 JOIN vpn_services s ON s.id=e.service_id AND s.tenant_id=e.tenant_id AND s.enabled
 JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
 JOIN imported_subscription_host_services hs ON hs.service_id=s.id AND hs.tenant_id=s.tenant_id
 JOIN imported_subscription_profiles head ON head.revision_id=hs.revision_id AND head.tenant_id=hs.tenant_id
 JOIN imported_subscription_revisions r ON r.id=head.revision_id AND r.tenant_id=head.tenant_id AND r.import_id=head.import_id
 JOIN remnawave_import_heads source ON source.import_id=r.import_id AND source.inventory_sha256=r.inventory_sha256
 JOIN bot_profiles bp ON bp.tenant_id=c.tenant_id AND bp.import_id=r.import_id AND bp.inventory_sha256=r.inventory_sha256
 JOIN node_xray_profile_bindings b ON b.service_id=s.id AND b.tenant_id=s.tenant_id AND b.node_id=s.node_id AND b.source_enabled
 JOIN node_xray_profiles runtime ON runtime.node_id=s.node_id AND runtime.tenant_id=s.tenant_id AND runtime.import_id=r.import_id
 WHERE c.id=$1::uuid AND c.status='active' AND NOT c.remnawave_hold
 AND (c.expires_at IS NULL OR c.expires_at>now()) AND NOT vpn_client_quota_exceeded(c.id)
 AND head.state='active' AND head.activated_at IS NOT NULL AND head.activation_sha256 IS NOT NULL
 AND bp.state IN ('active','paused') AND bp.source_identity_reviewed AND bp.activated_at IS NOT NULL
 AND runtime.state='active' AND runtime.adoption_sha256 IS NOT NULL AND runtime.activated_at IS NOT NULL
 ORDER BY r.id,hs.source_host_id,s.id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.VPNClientConnection{}
	bundles := map[string]ImportedSubscriptionBundle{}
	seen := map[string]bool{}
	for rows.Next() {
		var c model.VPNClientConnection
		var tenant, revision, digest, inventory, hostID string
		var wire []byte
		if err = rows.Scan(&tenant, &c.ClientID, &c.ClientName, &c.UUID, &revision, &digest, &wire, &inventory, &hostID, &c.ServiceID, &c.ServiceName, &c.SubscriptionName, &c.Protocol, &c.Transport, &c.Security, &c.RuntimeCore); err != nil {
			return nil, err
		}
		if !tenantScopeAllowed(ctx, tenant) {
			return nil, ErrNotFound
		}
		bundle, ok := bundles[revision]
		if !ok {
			sum := sha256.Sum256(wire)
			if hex.EncodeToString(sum[:]) != digest || json.Unmarshal(wire, &bundle) != nil || bundle.Version != 1 || bundle.Hosts.InventorySHA256 != inventory || bundle.Policy.InventorySHA256 != inventory {
				return nil, ErrImportedSubscriptionIdentity
			}
			bundles[revision] = bundle
		}
		key := revision + ":" + hostID
		if seen[key] {
			continue
		}
		found := false
		for _, bound := range bundle.Hosts.Hosts {
			if bound.SourceHostID != hostID {
				continue
			}
			authorized := false
			for _, id := range bound.ServiceIDs {
				if id == c.ServiceID {
					authorized = true
				}
			}
			if !authorized {
				return nil, ErrImportedSubscriptionIdentity
			}
			host := bound.Host
			if c.SubscriptionName != "" {
				host.Name = c.SubscriptionName
			}
			if _, err = subscriptioncompat.ShareURI(host, c.UUID); err != nil {
				return nil, ErrImportedSubscriptionIdentity
			}
			c.ImportedProfile, err = json.Marshal(host)
			if err != nil {
				return nil, err
			}
			c.Address, c.Port = host.Address, host.Port
			c.ServerName, _ = host.SecurityOptions["serverName"].(string)
			c.Fingerprint, _ = host.SecurityOptions["fingerprint"].(string)
			c.ShortID, _ = host.SecurityOptions["shortId"].(string)
			c.Password, _ = host.SecurityOptions["publicKey"].(string)
			out = append(out, c)
			seen[key] = true
			found = true
			break
		}
		if !found {
			return nil, ErrImportedSubscriptionIdentity
		}
	}
	return out, rows.Err()
}

func nativeSubscriptionHost(c model.VPNClientConnection, brand string) (subscriptioncompat.Host, error) {
	c.BrandName = brand
	h := subscriptioncompat.Host{Name: c.DisplayName(), Address: c.Address, Port: c.Port, Protocol: c.Protocol, Transport: c.Transport, Security: c.Security,
		ProtocolOptions: subscriptioncompat.Options{}, TransportOptions: subscriptioncompat.Options{}, SecurityOptions: subscriptioncompat.Options{"serverName": c.ServerName, "fingerprint": c.Fingerprint}}
	if h.Protocol == "shadowsocks" {
		h.NativeShadowsocksPassword = c.Password
		return h, subscriptioncompat.ValidateHost(h)
	}
	if h.Protocol == "vless" {
		h.ProtocolOptions["encryption"] = "none"
		h.ProtocolOptions["flow"] = ""
	}
	if h.Security == "reality" {
		h.SecurityOptions["publicKey"] = c.Password
		h.SecurityOptions["shortId"] = c.ShortID
	}
	if h.Security == "tls" {
		h.SecurityOptions["fingerprint"] = "chrome"
	}
	switch h.Transport {
	case "ws", "xhttp":
		path, ok := model.XHTTPPath(c.ServiceID)
		if !ok {
			return h, subscriptioncompat.ErrProfile
		}
		h.TransportOptions["path"] = path
		if h.Transport == "ws" {
			h.TransportOptions["host"] = c.ServerName
		} else {
			h.TransportOptions["mode"] = "auto"
		}
	case "grpc":
		name, ok := model.GRPCServiceName(c.ServiceID)
		if !ok {
			return h, subscriptioncompat.ErrProfile
		}
		h.TransportOptions["serviceName"] = name
	}
	if h.Protocol == "hysteria2" {
		h.Protocol = "hysteria"
		h.Transport = "hysteria"
		h.ProtocolOptions["version"] = 2
	}
	_, err := subscriptioncompat.ShareURI(h, c.UUID)
	return h, err
}
