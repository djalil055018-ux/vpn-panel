package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/subscriptioncompat"
	"vpn-platform/internal/xrayprofile"
)

var ErrImportedSubscriptionHeld = errors.New("imported public subscriptions are not ready for activation")
var ErrImportedSubscriptionIdentity = errors.New("imported public subscription identity differs from reviewed source")

type ImportedSubscriptionBundle struct {
	Version   int                                    `json:"version"`
	Hosts     subscriptioncompat.Projection          `json:"hosts"`
	Policy    subscriptioncompat.PolicyProjection    `json:"policy"`
	Templates map[string]subscriptioncompat.Template `json:"templates"`
}
type ImportedSubscriptionPreparation struct {
	RevisionID       string `json:"revision_id"`
	InventorySHA256  string `json:"inventory_sha256"`
	SettingsSHA256   string `json:"settings_sha256"`
	BundleSHA256     string `json:"bundle_sha256"`
	Hosts            int    `json:"hosts"`
	Squads           int    `json:"squads"`
	ExternalAccounts int    `json:"external_accounts"`
	Templates        int    `json:"templates"`
	State            string `json:"state"`
}

// PrepareImportedSubscriptions stores a reviewed immutable public projection.
// It never grants services, releases holds, changes credentials or node desired
// state, creates public aliases, activates the bridge or contacts source nodes.
func (p *Postgres) PrepareImportedSubscriptions(ctx context.Context, tenant, importID, reviewedInventorySHA, reviewedSettingsSHA string, settings []byte) (out ImportedSubscriptionPreparation, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	if !xrayPreparationUUID.MatchString(tenant) || !xrayPreparationUUID.MatchString(importID) || !xrayPreparationDigest.MatchString(reviewedInventorySHA) || !xrayPreparationDigest.MatchString(reviewedSettingsSHA) || len(settings) == 0 || len(settings) > 16<<20 {
		return out, ErrImportedSubscriptionIdentity
	}
	settingsDigest := sha256.Sum256(settings)
	if hex.EncodeToString(settingsDigest[:]) != reviewedSettingsSHA {
		return out, ErrRemnawaveReview
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	defer func() {
		var e *pgconn.PgError
		if errors.As(err, &e) && (e.Code == "23505" || e.Code == "23503" || e.Code == "23514" || e.Code == "55000") {
			err = ErrImportedSubscriptionIdentity
		}
	}()
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid AND state='held'`, importID, tenant).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, origin); err != nil {
		return out, err
	}
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var inventory []byte
	var digest string
	err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256 FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held' FOR UPDATE OF h`, importID, tenant).Scan(&inventory, &digest)
	if err != nil {
		return out, err
	}
	if digest != reviewedInventorySHA {
		return out, ErrRemnawaveReview
	}
	var botImport, botDigest, botState string
	err = tx.QueryRow(ctx, `SELECT import_id::text,inventory_sha256,state FROM bot_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, tenant).Scan(&botImport, &botDigest, &botState)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrImportedSubscriptionHeld
	}
	if err != nil {
		return out, err
	}
	if botImport != importID || botDigest != digest || botState != "held" {
		return out, ErrImportedSubscriptionHeld
	}
	var oldImport, oldRevision, oldState string
	err = tx.QueryRow(ctx, `SELECT import_id::text,revision_id::text,state FROM imported_subscription_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, tenant).Scan(&oldImport, &oldRevision, &oldState)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if err == nil && (oldImport != importID || oldState != "prepared") {
		return out, ErrImportedSubscriptionHeld
	}
	var changed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM remnawave_import_clients m JOIN vpn_clients c ON c.id=m.client_id
 WHERE m.import_id=$1::uuid AND (c.tenant_id<>$2::uuid OR NOT c.remnawave_hold OR c.status<>'disabled'
 OR EXISTS(SELECT 1 FROM node_client_traffic_cursors x WHERE x.client_id=c.id)))`, importID, tenant).Scan(&changed)
	if err != nil {
		return out, err
	}
	if changed {
		return out, ErrImportedSubscriptionHeld
	}
	// Registry identities are immutable. Lock node state in stable native ID order
	// so a simultaneous activation cannot race preparation.
	type registration struct {
		NodeID string
		Source *xrayprofile.SourceNodeProjection
	}
	registered := []registration{}
	rows, err := tx.Query(ctx, `SELECT p.node_id::text,p.source_node_id::text,p.source_profile_id::text,p.profile_sha256,p.profile
 FROM node_xray_profiles p JOIN nodes n ON n.id=p.node_id AND n.tenant_id=p.tenant_id
 WHERE p.import_id=$1::uuid AND p.tenant_id=$2::uuid AND p.state='prepared' AND n.desired_generation=0
 ORDER BY p.node_id FOR SHARE OF n,p`, importID, tenant)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var n registration
		source := &xrayprofile.SourceNodeProjection{InventorySHA256: digest}
		var wire []byte
		var profileSHA string
		if err = rows.Scan(&n.NodeID, &source.NodeID, &source.ProfileID, &profileSHA, &wire); err != nil {
			rows.Close()
			return out, err
		}
		if json.Unmarshal(wire, &source.Profile) != nil || source.Profile == nil || source.Profile.SHA256 != profileSHA {
			rows.Close()
			return out, ErrImportedSubscriptionIdentity
		}
		n.Source = source
		registered = append(registered, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(registered) == 0 {
		return out, ErrImportedSubscriptionHeld
	}
	projections := []*xrayprofile.SourceNodeProjection{}
	for _, n := range registered {
		var inUse bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM desired_states WHERE node_id=$1::uuid)
   OR EXISTS(SELECT 1 FROM deployments WHERE node_id=$1::uuid)
   OR EXISTS(SELECT 1 FROM vpn_effective_client_services e JOIN vpn_services s ON s.id=e.service_id AND s.tenant_id=e.tenant_id WHERE s.node_id=$1::uuid)`, n.NodeID).Scan(&inUse)
		if err != nil {
			return out, err
		}
		if inUse {
			return out, ErrImportedSubscriptionHeld
		}
		rows, err = tx.Query(ctx, `SELECT b.source_inbound_id::text,b.inbound_tag,b.source_enabled,b.service_spec,s.enabled
 FROM node_xray_profile_bindings b JOIN vpn_services s ON s.id=b.service_id AND s.node_id=b.node_id AND s.tenant_id=b.tenant_id
 WHERE b.node_id=$1::uuid AND b.tenant_id=$2::uuid ORDER BY b.inbound_tag`, n.NodeID, tenant)
		if err != nil {
			return out, err
		}
		assignments := []xrayprofile.SourceServiceAssignment{}
		bindings := map[string]xrayprofile.SourceService{}
		for rows.Next() {
			var s xrayprofile.SourceService
			var wire []byte
			var enabled bool
			if err = rows.Scan(&s.InboundID, &s.InboundTag, &s.Enabled, &wire, &enabled); err != nil {
				rows.Close()
				return out, err
			}
			if enabled || json.Unmarshal(wire, &s.Service) != nil {
				rows.Close()
				return out, ErrImportedSubscriptionHeld
			}
			bindings[s.InboundID] = s
			assignments = append(assignments, xrayprofile.SourceServiceAssignment{InboundID: s.InboundID, ServiceID: s.Service.ID, TLS: s.Service.TLS})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		fresh, e := xrayprofile.ProjectSourceNode(inventory, n.Source.NodeID, assignments)
		if e != nil || fresh.ProfileID != n.Source.ProfileID || fresh.Profile.SHA256 != n.Source.Profile.SHA256 || xrayprofile.Validate(n.Source.Profile) != nil {
			return out, ErrImportedSubscriptionIdentity
		}
		for _, s := range fresh.Services {
			if !reflect.DeepEqual(s, bindings[s.InboundID]) {
				return out, ErrImportedSubscriptionIdentity
			}
		}
		projections = append(projections, fresh)
	}
	hosts, e := subscriptioncompat.ProjectInventory(inventory, projections)
	if e != nil {
		return out, ErrImportedSubscriptionIdentity
	}
	policy, e := subscriptioncompat.ProjectPolicies(inventory, settings)
	if e != nil {
		return out, ErrImportedSubscriptionIdentity
	}
	templates, e := subscriptioncompat.ProjectTemplates(settings)
	if e != nil {
		return out, ErrImportedSubscriptionIdentity
	}
	if policy.InventorySHA256 != digest || policy.SettingsSHA256 != reviewedSettingsSHA {
		return out, ErrRemnawaveReview
	}
	bundle := ImportedSubscriptionBundle{Version: 1, Hosts: hosts, Policy: policy, Templates: templates}
	wire, e := json.Marshal(bundle)
	if e != nil || len(wire) > 8<<20 {
		return out, ErrImportedSubscriptionIdentity
	}
	bundleDigest := sha256.Sum256(wire)
	bundleSHA := hex.EncodeToString(bundleDigest[:])
	out = ImportedSubscriptionPreparation{InventorySHA256: digest, SettingsSHA256: reviewedSettingsSHA, BundleSHA256: bundleSHA, Hosts: len(hosts.Hosts), Squads: len(hosts.Squads), Templates: len(templates), State: "prepared"}
	var existingSHA string
	err = tx.QueryRow(ctx, `SELECT id::text,bundle_sha256 FROM imported_subscription_revisions WHERE import_id=$1::uuid AND inventory_sha256=$2 AND settings_sha256=$3`, importID, digest, reviewedSettingsSHA).Scan(&out.RevisionID, &existingSHA)
	existing := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if existing && existingSHA != bundleSHA {
		return out, ErrImportedSubscriptionIdentity
	}
	if !existing {
		if _, err = tx.Exec(ctx, `INSERT INTO remnawave_subscription_settings(import_id,settings_sha256,source) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING`, importID, reviewedSettingsSHA, settings); err != nil {
			return out, err
		}
		err = tx.QueryRow(ctx, `INSERT INTO imported_subscription_revisions(tenant_id,import_id,inventory_sha256,settings_sha256,bundle_sha256,bundle) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::bytea) RETURNING id::text`, tenant, importID, digest, reviewedSettingsSHA, bundleSHA, wire).Scan(&out.RevisionID)
		if err != nil {
			return out, err
		}
		for _, h := range hosts.Hosts {
			for _, service := range h.ServiceIDs {
				if _, err = tx.Exec(ctx, `INSERT INTO imported_subscription_host_services(revision_id,tenant_id,source_host_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)`, out.RevisionID, tenant, h.SourceHostID, service); err != nil {
					return out, err
				}
			}
		}
		for _, s := range hosts.Squads {
			for _, service := range s.ServiceIDs {
				if _, err = tx.Exec(ctx, `INSERT INTO imported_subscription_squad_services(revision_id,tenant_id,source_squad_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)`, out.RevisionID, tenant, s.SourceSquadID, service); err != nil {
					return out, err
				}
			}
		}
		for legacyID, external := range policy.UserExternal {
			var alive, tombstone bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=$2 AND source_present AND client_id IS NOT NULL),
 EXISTS(SELECT 1 FROM remnawave_import_clients WHERE import_id=$3::uuid AND source_user_id=$2 AND client_id IS NULL AND deleted_at IS NOT NULL AND deleted_client_id IS NOT NULL)`, tenant, legacyID, importID).Scan(&alive, &tombstone)
			if err != nil {
				return out, err
			}
			if !alive {
				if tombstone {
					continue
				}
				return out, ErrImportedSubscriptionIdentity
			}
			if _, err = tx.Exec(ctx, `INSERT INTO imported_subscription_external_accounts(revision_id,tenant_id,legacy_id,source_external_id) VALUES($1::uuid,$2::uuid,$3,$4::uuid)`, out.RevisionID, tenant, legacyID, external); err != nil {
				return out, err
			}
		}
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM imported_subscription_external_accounts WHERE revision_id=$1::uuid AND tenant_id=$2::uuid`, out.RevisionID, tenant).Scan(&out.ExternalAccounts)
	if err != nil {
		return out, err
	}
	if oldRevision != out.RevisionID {
		if _, err = tx.Exec(ctx, `INSERT INTO imported_subscription_profiles(tenant_id,import_id,revision_id) VALUES($1::uuid,$2::uuid,$3::uuid)
 ON CONFLICT(tenant_id) DO UPDATE SET revision_id=excluded.revision_id,prepared_at=now()`, tenant, importID, out.RevisionID); err != nil {
			return out, err
		}
		actor, actorID := accessActor(ctx)
		if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'imported_subscription.prepared',$2,$3,
 jsonb_build_object('revision_id',$4::text,'inventory_sha256',$5::text,'settings_sha256',$6::text,'bundle_sha256',$7::text,'hosts',$8::integer,'state','prepared'))`, tenant, actor, actorID, out.RevisionID, digest, reviewedSettingsSHA, bundleSHA, out.Hosts); err != nil {
			return out, err
		}
	}
	return out, tx.Commit(ctx)
}
