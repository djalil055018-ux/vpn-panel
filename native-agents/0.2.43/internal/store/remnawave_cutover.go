package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/xrayprofile"
)

var ErrRemnawaveCutover = errors.New("reviewed migration is not ready for runtime activation")

// These are owner attestations from the node-local handoff, not independent
// remote observations by Control Plane. They must be collected only after the
// old writer has stopped, restart has been fenced and rollback has been armed.
type RemnawaveNodeHandoff struct {
	NodeID              string `json:"node_id"`
	MaterialSHA256      string `json:"material_sha256"`
	HandoffSHA256       string `json:"handoff_sha256"`
	SourceStopped       bool   `json:"source_stopped"`
	SourceRestartFenced bool   `json:"source_restart_fenced"`
	MaterialPublished   bool   `json:"material_published"`
	RollbackArmed       bool   `json:"rollback_armed"`
}
type RemnawaveCutoverRequest struct {
	TenantID               string                 `json:"tenant_id"`
	InventorySHA256        string                 `json:"inventory_sha256"`
	SubscriptionRevisionID string                 `json:"subscription_revision_id"`
	BundleSHA256           string                 `json:"bundle_sha256"`
	CoreReleaseID          string                 `json:"core_release_id"`
	SourceFreezeSHA256     string                 `json:"source_freeze_sha256"`
	SourceFrozenAt         time.Time              `json:"source_frozen_at"`
	RollbackDeadline       time.Time              `json:"rollback_deadline"`
	Nodes                  []RemnawaveNodeHandoff `json:"nodes"`
}
type RemnawaveCutoverNode struct {
	NodeID     string `json:"node_id"`
	Generation int64  `json:"generation"`
	Services   int    `json:"services"`
}
type RemnawaveCutoverResult struct {
	ImportID                  string                 `json:"import_id"`
	State                     string                 `json:"state"`
	PhysicalProof             string                 `json:"physical_proof"`
	InventorySHA256           string                 `json:"inventory_sha256"`
	RequestSHA256             string                 `json:"request_sha256"`
	Clients                   int                    `json:"clients"`
	Deleted                   int                    `json:"deleted"`
	Nodes                     []RemnawaveCutoverNode `json:"nodes"`
	PublicSubscriptionsActive bool                   `json:"public_subscriptions_active"`
	BotActive                 bool                   `json:"bot_active"`
}

func normalizeCutoverRequest(req RemnawaveCutoverRequest) (RemnawaveCutoverRequest, []byte, string, error) {
	for _, id := range []string{req.TenantID, req.SubscriptionRevisionID, req.CoreReleaseID} {
		if !xrayPreparationUUID.MatchString(id) {
			return req, nil, "", ErrRemnawaveCutover
		}
	}
	for _, digest := range []string{req.InventorySHA256, req.BundleSHA256, req.SourceFreezeSHA256} {
		if !xrayPreparationDigest.MatchString(digest) {
			return req, nil, "", ErrRemnawaveCutover
		}
	}
	if len(req.Nodes) == 0 || len(req.Nodes) > 64 || req.SourceFrozenAt.IsZero() || req.RollbackDeadline.IsZero() {
		return req, nil, "", ErrRemnawaveCutover
	}
	req.Nodes = append([]RemnawaveNodeHandoff(nil), req.Nodes...)
	sort.Slice(req.Nodes, func(i, j int) bool { return req.Nodes[i].NodeID < req.Nodes[j].NodeID })
	for i, n := range req.Nodes {
		if !xrayPreparationUUID.MatchString(n.NodeID) || !xrayPreparationDigest.MatchString(n.MaterialSHA256) || !xrayPreparationDigest.MatchString(n.HandoffSHA256) ||
			!n.SourceStopped || !n.SourceRestartFenced || !n.MaterialPublished || !n.RollbackArmed || (i > 0 && n.NodeID == req.Nodes[i-1].NodeID) {
			return req, nil, "", ErrRemnawaveCutover
		}
	}
	req.SourceFrozenAt = req.SourceFrozenAt.UTC().Truncate(time.Microsecond)
	req.RollbackDeadline = req.RollbackDeadline.UTC().Truncate(time.Microsecond)
	raw, err := json.Marshal(req)
	if err != nil {
		return req, nil, "", err
	}
	sum := sha256.Sum256(raw)
	return req, raw, hex.EncodeToString(sum[:]), nil
}

// BeginRemnawaveRuntimeCutover publishes all source nodes and releases eligible
// source memberships in one database transaction. It preserves credentials and
// quota baselines. Bot management and public subscriptions remain unavailable
// until a separate verified publication step. No source/Agent restart is issued
// here; delivering generation 1 authorizes registered Agents to apply it.
//
// This is an internal candidate operation. It is intentionally not registered
// as an HTTP route until publication and physical rollback orchestration exist.
func (p *Postgres) BeginRemnawaveRuntimeCutover(ctx context.Context, importID string, input RemnawaveCutoverRequest) (out RemnawaveCutoverResult, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	if !xrayPreparationUUID.MatchString(importID) {
		return out, ErrRemnawaveCutover
	}
	req, requestRaw, requestSHA, err := normalizeCutoverRequest(input)
	if err != nil {
		return out, err
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var origin, importState string
	err = tx.QueryRow(ctx, `SELECT source_origin,state FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid`, importID, req.TenantID).Scan(&origin, &importState)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, origin); err != nil {
		return out, err
	}
	if err = lockTenantResource(ctx, tx, req.TenantID); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, req.TenantID); err != nil {
		return out, err
	}
	var previousSHA, previousState string
	var previousRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_sha256,state,result FROM remnawave_cutovers WHERE import_id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, importID, req.TenantID).Scan(&previousSHA, &previousState, &previousRaw)
	if err == nil {
		if previousSHA != requestSHA {
			return out, ErrRemnawaveCutover
		}
		if json.Unmarshal(previousRaw, &out) != nil {
			return out, ErrRemnawaveCutover
		}
		out.State = previousState
		return out, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	// Re-read after acquiring source/tenant locks; another cutover may have won.
	var raw []byte
	var digest string
	err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256,i.state FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid FOR UPDATE OF i,h`, importID, req.TenantID).Scan(&raw, &digest, &importState)
	if err != nil {
		return out, err
	}
	if importState != "held" || digest != req.InventorySHA256 {
		return out, ErrRemnawaveReview
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	if req.SourceFrozenAt.After(now) || now.Sub(req.SourceFrozenAt) > 5*time.Minute || req.RollbackDeadline.Before(now.Add(time.Minute)) || req.RollbackDeadline.After(now.Add(15*time.Minute)) {
		return out, ErrRemnawaveCutover
	}
	inv, report, err := remnawave.Parse(raw)
	if err != nil {
		return out, err
	}
	// The final inventory must follow the source write freeze, not precede it.
	if report.SHA256 != digest || inv.CapturedAt.Before(req.SourceFrozenAt) || inv.CapturedAt.After(now) {
		return out, ErrRemnawaveReview
	}
	var prepared bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bot_profiles WHERE tenant_id=$1::uuid AND import_id=$2::uuid AND inventory_sha256=$3 AND state='held' AND activated_at IS NULL)
 AND EXISTS(SELECT 1 FROM imported_subscription_profiles p JOIN imported_subscription_revisions r ON r.id=p.revision_id AND r.tenant_id=p.tenant_id
 WHERE p.tenant_id=$1::uuid AND p.import_id=$2::uuid AND p.state='prepared' AND p.revision_id=$4::uuid AND r.inventory_sha256=$3 AND r.bundle_sha256=$5)`, req.TenantID, importID, digest, req.SubscriptionRevisionID, req.BundleSHA256).Scan(&prepared)
	if err != nil {
		return out, err
	}
	if !prepared {
		return out, ErrRemnawaveCutover
	}
	if _, err = tx.Exec(ctx, `SELECT tenant_id FROM bot_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, req.TenantID); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `SELECT tenant_id FROM imported_subscription_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, req.TenantID); err != nil {
		return out, err
	}
	var release model.CoreRelease
	err = tx.QueryRow(ctx, `SELECT core_type,version,download_url,sha256,channel FROM core_releases WHERE id=$1::uuid AND approved AND NOT revoked AND core_type='xray' AND os='linux' AND architecture='amd64' FOR SHARE`, req.CoreReleaseID).Scan(&release.Type, &release.Version, &release.DownloadURL, &release.SHA256, &release.Channel)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrPinnedCoreReleaseUnavailable
	}
	if err != nil {
		return out, err
	}
	if !xrayprofile.CoreCompatible(release) {
		return out, ErrNodeRuntime
	}
	if err = validateCutoverNodesTx(ctx, tx, req, importID, raw); err != nil {
		return out, err
	}
	clients, deleted, err := validateCutoverAccountsTx(ctx, tx, req, importID, inv, raw)
	if err != nil {
		return out, err
	}
	if err = validateCutoverPlansTx(ctx, tx, req, raw); err != nil {
		return out, err
	}

	// All validation precedes publication. Native grant projection deliberately
	// includes paused bot profiles with activated_at, while bot API rejects paused.
	if _, err = tx.Exec(ctx, `UPDATE bot_profiles SET state='paused',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, req.TenantID); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE vpn_access_plans p SET enabled=true FROM bot_squads s WHERE s.tenant_id=$1::uuid AND s.source_present AND s.plan_id=p.id AND p.tenant_id=s.tenant_id`, req.TenantID); err != nil {
		return out, err
	}
	for _, u := range inv.Users {
		state := "active"
		if u.Status == "DISABLED" {
			state = "disabled"
		}
		if _, err = tx.Exec(ctx, `UPDATE vpn_clients c SET remnawave_hold=false,status=$3,updated_at=now() FROM remnawave_import_clients m WHERE m.import_id=$1::uuid AND m.source_user_id=$2 AND m.client_id=c.id AND m.source_present AND m.deleted_at IS NULL`, importID, u.ID, state); err != nil {
			return out, err
		}
	}
	out = RemnawaveCutoverResult{ImportID: importID, State: "verifying", PhysicalProof: "owner_attestation", InventorySHA256: digest, RequestSHA256: requestSHA, Clients: clients, Deleted: deleted, Nodes: []RemnawaveCutoverNode{}}
	for _, node := range req.Nodes {
		if _, err = tx.Exec(ctx, `UPDATE node_xray_profiles SET state='active',adoption_sha256=$2,activated_at=now() WHERE node_id=$1::uuid`, node.NodeID, node.MaterialSHA256); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `UPDATE vpn_services s SET enabled=b.source_enabled FROM node_xray_profile_bindings b WHERE b.node_id=$1::uuid AND s.id=b.service_id AND s.tenant_id=b.tenant_id`, node.NodeID); err != nil {
			return out, err
		}
		desired, releaseID, e := buildNodeDesiredWithBaseTx(ctx, tx, node.NodeID, 0, model.DesiredState{Core: release}, req.CoreReleaseID)
		if e != nil {
			return out, e
		}
		if e = saveDesiredStateTx(ctx, tx, node.NodeID, desired, releaseID); e != nil {
			return out, e
		}
		out.Nodes = append(out.Nodes, RemnawaveCutoverNode{NodeID: node.NodeID, Generation: desired.Generation, Services: len(desired.Services)})
	}
	resultRaw, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO remnawave_cutovers(import_id,tenant_id,request_sha256,inventory_sha256,subscription_revision_id,request,result) VALUES($1::uuid,$2::uuid,$3,$4,$5::uuid,$6::jsonb,$7::jsonb)`, importID, req.TenantID, requestSHA, digest, req.SubscriptionRevisionID, string(requestRaw), string(resultRaw)); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE remnawave_imports SET state='activating' WHERE id=$1::uuid`, importID); err != nil {
		return out, err
	}
	actor, actorID := accessActor(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'remnawave.runtime_activation_started',$2,$3,jsonb_build_object('import_id',$4::text,'request_sha256',$5::text,'inventory_sha256',$6::text,'nodes',$7::integer,'clients',$8::integer,'physical_proof','owner_attestation','state','verifying'))`, req.TenantID, actor, actorID, importID, requestSHA, digest, len(out.Nodes), clients); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

// Helper implementations are kept in remnawave_cutover_validation.go so the
// atomic write path above can be reviewed separately from source comparisons.
