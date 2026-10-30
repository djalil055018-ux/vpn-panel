package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/subscriptioncompat"
)

var importedAlias = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var ErrSubscriptionNotImported = errors.New("subscription client has no imported bot account")

// A lookup uses an opaque legacy alias OR a native client ID obtained from
// ResolveVPNClientSubscription after signature/version/hash validation.
// NativeClientID is an internal authenticated selector, not an HTTP parameter.
type ImportedSubscriptionLookup struct {
	Alias          string
	NativeClientID string
}

// This private snapshot contains bearer material. It is intentionally excluded
// from JSON; handlers render only the specifically selected public format.
type ImportedSubscriptionSnapshot struct {
	Auto       subscriptioncompat.AutoProfile         `json:"-"`
	BrandName  string                                 `json:"-"`
	ClientID   string                                 `json:"-"`
	Credential string                                 `json:"-"`
	Account    subscriptioncompat.ResponseAccount     `json:"-"`
	Policy     subscriptioncompat.Policy              `json:"-"`
	Hosts      []subscriptioncompat.Host              `json:"-"`
	Templates  map[string]subscriptioncompat.Template `json:"-"`
	Page       json.RawMessage                        `json:"-"`
}

// ReadImportedSubscription uses one repeatable read so account state, current
// alias, policy and native effective grants belong to the same database view.
// Prepared/held profiles cannot resolve. Disabled/expired/limited accounts can
// receive display notices, but never a runtime credential or real host.
func (p *Postgres) ReadImportedSubscription(ctx context.Context, lookup ImportedSubscriptionLookup) (out ImportedSubscriptionSnapshot, err error) {
	defer func() {
		if err != nil {
			out = ImportedSubscriptionSnapshot{}
		}
	}()
	if (lookup.Alias == "") == (lookup.NativeClientID == "") {
		return out, ErrNotFound
	}
	var native any
	if lookup.Alias != "" {
		if !importedAlias.MatchString(lookup.Alias) {
			return out, ErrNotFound
		}
	} else {
		if !xrayPreparationUUID.MatchString(lookup.NativeClientID) {
			return out, ErrNotFound
		}
		native = lookup.NativeClientID
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if native != nil {
		var imported bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bot_accounts a JOIN bot_profiles b ON b.tenant_id=a.tenant_id WHERE b.profile_kind='imported' AND (a.client_id=$1::uuid OR a.deleted_client_id=$1::uuid))`, native).Scan(&imported); err != nil {
			return out, err
		}
		if !imported {
			return out, ErrSubscriptionNotImported
		}
	}
	var tenant, revision, importID, digest, inventorySHA string
	var external *string
	var bundleWire []byte
	err = tx.QueryRow(ctx, `SELECT b.tenant_id::text,r.id::text,r.import_id::text,r.bundle_sha256,r.bundle,r.inventory_sha256,
 c.id::text,c.vless_uuid::text,b.username,a.alias,p.subscription_base||a.alias,
 q.baseline_bytes+q.uplink_bytes+q.downlink_bytes,b.lifetime_offset_bytes+q.uplink_bytes+q.downlink_bytes,q.limit_bytes,COALESCE(c.expires_at,'2099-01-01T00:00:00Z'::timestamptz),
 CASE WHEN c.status='disabled' THEN 'DISABLED' WHEN c.expires_at<=now() THEN 'EXPIRED' WHEN vpn_client_quota_exceeded(c.id) THEN 'LIMITED' ELSE 'ACTIVE' END,
 ep.source_external_id::text,coalesce(brand.display_name,'PAUK')
 FROM bot_accounts b JOIN vpn_clients c ON c.id=b.client_id AND c.tenant_id=b.tenant_id
 LEFT JOIN tenant_branding brand ON brand.tenant_id=b.tenant_id
 JOIN bot_profiles p ON p.tenant_id=b.tenant_id
 JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id AND a.state='active'
 JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
 JOIN imported_subscription_profiles head ON head.tenant_id=b.tenant_id AND head.import_id=p.import_id
 JOIN imported_subscription_revisions r ON r.id=head.revision_id AND r.tenant_id=head.tenant_id AND r.import_id=head.import_id
 JOIN remnawave_import_heads source ON source.import_id=p.import_id
 LEFT JOIN imported_subscription_external_accounts ep ON ep.revision_id=r.id AND ep.tenant_id=b.tenant_id AND ep.legacy_id=b.legacy_id
 WHERE (a.alias=$1 OR ($2::uuid IS NOT NULL AND c.id=$2::uuid))
 AND b.source_present AND b.deleted_at IS NULL AND NOT c.remnawave_hold
 AND head.state='active' AND head.activated_at IS NOT NULL AND head.activation_sha256 IS NOT NULL
 AND p.state IN ('active','paused') AND p.source_identity_reviewed AND p.activated_at IS NOT NULL
 AND p.inventory_sha256=source.inventory_sha256 AND r.inventory_sha256=source.inventory_sha256`, lookup.Alias, native).Scan(
		&tenant, &revision, &importID, &digest, &bundleWire, &inventorySHA, &out.ClientID, &out.Credential, &out.Account.Username, &out.Account.Alias, &out.Account.SubscriptionURL,
		&out.Account.UsedBytes, &out.Account.LifetimeBytes, &out.Account.LimitBytes, &out.Account.ExpiresAt, &out.Account.Status, &external, &out.BrandName)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	// Administrative callers cannot cross a tenant boundary through this helper.
	if principal, ok := TenantPrincipal(ctx); ok && principal.TenantID != tenant {
		return out, ErrNotFound
	}
	bundleHash := sha256.Sum256(bundleWire)
	var bundle ImportedSubscriptionBundle
	if hex.EncodeToString(bundleHash[:]) != digest || json.Unmarshal(bundleWire, &bundle) != nil || bundle.Version != 1 ||
		bundle.Hosts.InventorySHA256 != inventorySHA || bundle.Policy.InventorySHA256 != inventorySHA {
		return out, ErrImportedSubscriptionIdentity
	}
	out.Policy = bundle.Policy.Global
	if external != nil {
		policy, ok := bundle.Policy.External[*external]
		if !ok {
			return out, ErrImportedSubscriptionIdentity
		}
		out.Policy = policy
	}
	if out.Policy.Validate() != nil || out.Policy.PageID == nil || bundle.Policy.Pages[*out.Policy.PageID] == nil {
		return out, ErrImportedSubscriptionIdentity
	}
	out.Page = bundle.Policy.Pages[*out.Policy.PageID]
	out.Templates = bundle.Templates
	out.Hosts = []subscriptioncompat.Host{}
	services := []string{}
	if out.Account.Status == "ACTIVE" {
		imported, e := listImportedVPNClientConnections(ctx, tx, out.ClientID)
		if e != nil {
			return out, e
		}
		cascades, e := listCascadeVPNClientConnections(ctx, tx, out.ClientID)
		if e != nil {
			return out, e
		}
		imported = append(imported, cascades...)
		for _, c := range imported {
			var h subscriptioncompat.Host
			if e = json.Unmarshal(c.ImportedProfile, &h); e != nil {
				return out, e
			}
			out.Hosts = append(out.Hosts, h)
			services = append(services, c.ServiceID)
		}
		native, e := listNativeVPNClientConnections(ctx, tx, out.ClientID)
		if e != nil {
			return out, e
		}
		for _, c := range native {
			// Native file protocols keep their explicit download routes.
			// Shadowsocks has separate per-service secrets, not the VLESS credential.
			if c.Protocol != "vless" && c.Protocol != "trojan" && c.Protocol != "hysteria2" {
				continue
			}
			h, e := nativeSubscriptionHost(c, out.BrandName)
			if e != nil {
				return out, e
			}
			out.Hosts = append(out.Hosts, h)
			services = append(services, c.ServiceID)
		}

	}
	out.Auto, err = readSubscriptionAuto(ctx, tx, tenant, out.ClientID, services)
	if err != nil {
		return out, err
	}
	if len(out.Hosts) == 0 {
		out.Credential = ""
	}
	return out, tx.Commit(ctx)
}
