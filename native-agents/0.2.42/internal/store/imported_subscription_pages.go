package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"sort"
	"vpn-platform/internal/subscriptioncompat"
)

// Only a tenant-scoped reader may enumerate their active page configurations.
// Pausing bot mutations leaves already activated public subscriptions readable.
func (p *Postgres) ImportedSubscriptionPages(ctx context.Context) ([]subscriptioncompat.PageConfig, error) {
	principal, ok := TenantPrincipal(ctx)
	if !ok || principal.TenantID == "" || (principal.Role != "viewer" && principal.Role != "operator") {
		return nil, ErrNotFound
	}
	var wire []byte
	var digest, inventorySHA string
	err := p.Pool.QueryRow(ctx, `SELECT r.bundle,r.bundle_sha256,r.inventory_sha256
 FROM imported_subscription_profiles head
 JOIN imported_subscription_revisions r ON r.id=head.revision_id AND r.tenant_id=head.tenant_id AND r.import_id=head.import_id
 JOIN bot_profiles b ON b.tenant_id=head.tenant_id AND b.import_id=head.import_id
 JOIN remnawave_import_heads source ON source.import_id=head.import_id
 WHERE head.tenant_id=$1::uuid AND head.state='active' AND head.activated_at IS NOT NULL AND head.activation_sha256 IS NOT NULL
 AND b.state IN ('active','paused') AND b.activated_at IS NOT NULL AND b.source_identity_reviewed
 AND b.inventory_sha256=source.inventory_sha256 AND r.inventory_sha256=source.inventory_sha256`, principal.TenantID).Scan(&wire, &digest, &inventorySHA)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(wire)
	var bundle ImportedSubscriptionBundle
	if hex.EncodeToString(sum[:]) != digest || json.Unmarshal(wire, &bundle) != nil || bundle.Version != 1 ||
		bundle.Policy.InventorySHA256 != inventorySHA || bundle.Hosts.InventorySHA256 != inventorySHA ||
		len(bundle.Policy.Pages) == 0 || len(bundle.Policy.Pages) != len(bundle.Policy.PageDetails) {
		return nil, ErrImportedSubscriptionIdentity
	}
	out := make([]subscriptioncompat.PageConfig, 0, len(bundle.Policy.Pages))
	for id, body := range bundle.Policy.Pages {
		meta, ok := bundle.Policy.PageDetails[id]
		if !ok || meta.ID != id || meta.Name == "" || !json.Valid(body) {
			return nil, ErrImportedSubscriptionIdentity
		}
		out = append(out, subscriptioncompat.PageConfig{PageMetadata: meta, Config: body})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ViewPosition == out[j].ViewPosition {
			return out[i].ID < out[j].ID
		}
		return out[i].ViewPosition < out[j].ViewPosition
	})
	return out, nil
}
