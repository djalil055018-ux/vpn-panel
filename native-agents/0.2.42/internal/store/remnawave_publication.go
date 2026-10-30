package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

type RemnawavePublicationNode struct {
	NodeID              string    `json:"node_id"`
	Generation          int64     `json:"generation"`
	ProfileSHA256       string    `json:"profile_sha256"`
	ServiceIDs          []string  `json:"service_ids"`
	ExternalProofSHA256 string    `json:"external_proof_sha256"`
	GuardCommitSHA256   string    `json:"guard_commit_sha256"`
	GuardCommittedAt    time.Time `json:"guard_committed_at"`
	SourceStillFenced   bool      `json:"source_still_fenced"`
}
type RemnawavePublicationRequest struct {
	TenantID             string                     `json:"tenant_id"`
	RuntimeRequestSHA256 string                     `json:"runtime_request_sha256"`
	VerifiedAt           time.Time                  `json:"verified_at"`
	Nodes                []RemnawavePublicationNode `json:"nodes"`
}
type RemnawavePublicationResult struct {
	ImportID          string `json:"import_id"`
	State             string `json:"state"`
	PublicationSHA256 string `json:"publication_sha256"`
	PhysicalProof     string `json:"physical_proof"`
}

func normalizePublicationRequest(req RemnawavePublicationRequest) (RemnawavePublicationRequest, []byte, string, error) {
	if !xrayPreparationUUID.MatchString(req.TenantID) || !xrayPreparationDigest.MatchString(req.RuntimeRequestSHA256) || req.VerifiedAt.IsZero() || len(req.Nodes) == 0 || len(req.Nodes) > 64 {
		return req, nil, "", ErrRemnawaveCutover
	}
	req.VerifiedAt = req.VerifiedAt.UTC().Truncate(time.Microsecond)
	req.Nodes = append([]RemnawavePublicationNode(nil), req.Nodes...)
	sort.Slice(req.Nodes, func(i, j int) bool { return req.Nodes[i].NodeID < req.Nodes[j].NodeID })
	for i := range req.Nodes {
		n := &req.Nodes[i]
		if !xrayPreparationUUID.MatchString(n.NodeID) || n.Generation < 1 || !xrayPreparationDigest.MatchString(n.ProfileSHA256) || !xrayPreparationDigest.MatchString(n.ExternalProofSHA256) || !xrayPreparationDigest.MatchString(n.GuardCommitSHA256) || !n.SourceStillFenced || n.GuardCommittedAt.IsZero() || n.ServiceIDs == nil || len(n.ServiceIDs) > 256 || (i > 0 && n.NodeID == req.Nodes[i-1].NodeID) {
			return req, nil, "", ErrRemnawaveCutover
		}
		n.GuardCommittedAt = n.GuardCommittedAt.UTC().Truncate(time.Microsecond)
		n.ServiceIDs = append([]string{}, n.ServiceIDs...)
		sort.Strings(n.ServiceIDs)
		for j, id := range n.ServiceIDs {
			if !xrayPreparationUUID.MatchString(id) || (j > 0 && id == n.ServiceIDs[j-1]) {
				return req, nil, "", ErrRemnawaveCutover
			}
		}
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return req, nil, "", err
	}
	sum := sha256.Sum256(raw)
	return req, raw, hex.EncodeToString(sum[:]), nil
}

// PublishRemnawaveCutover opens public subscriptions and bot management together
// after native runtime convergence. External traffic and node-local guard commit
// receipts remain explicitly owner-attested: Control Plane does not contact SSH
// targets or claim to independently verify a supplied digest.
//
// Every physical rollback guard must be durably committed before this step, so
// a late timer cannot restore the old writer after bot mutations become visible.
// A failed publication is safely retryable while the native runtimes keep serving.
func (p *Postgres) PublishRemnawaveCutover(ctx context.Context, importID string, input RemnawavePublicationRequest) (out RemnawavePublicationResult, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	if !xrayPreparationUUID.MatchString(importID) {
		return out, ErrRemnawaveCutover
	}
	req, proofRaw, proofSHA, err := normalizePublicationRequest(input)
	if err != nil {
		return out, err
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid`, importID, req.TenantID).Scan(&origin)
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
	var state, runtimeSHA, inventorySHA, revision string
	var publishedSHA *string
	var requestRaw []byte
	var startedAt time.Time
	err = tx.QueryRow(ctx, `SELECT state,request_sha256,inventory_sha256,subscription_revision_id::text,publication_sha256,request,started_at FROM remnawave_cutovers WHERE import_id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, importID, req.TenantID).Scan(&state, &runtimeSHA, &inventorySHA, &revision, &publishedSHA, &requestRaw, &startedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrRemnawaveCutover
	}
	if err != nil {
		return out, err
	}
	if runtimeSHA != req.RuntimeRequestSHA256 {
		return out, ErrRemnawaveCutover
	}
	out = RemnawavePublicationResult{ImportID: importID, State: "active", PublicationSHA256: proofSHA, PhysicalProof: "owner_attestation"}
	if state == "active" {
		if publishedSHA == nil || *publishedSHA != proofSHA {
			return out, ErrRemnawaveCutover
		}
		// Exact replay never resumes an independently paused bot/public profile.
		return out, tx.Commit(ctx)
	}
	if state != "verifying" || publishedSHA != nil {
		return out, ErrRemnawaveCutover
	}
	var initial RemnawaveCutoverRequest
	if json.Unmarshal(requestRaw, &initial) != nil || initial.InventorySHA256 != inventorySHA || initial.SubscriptionRevisionID != revision || len(initial.Nodes) != len(req.Nodes) {
		return out, ErrRemnawaveCutover
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	if req.VerifiedAt.Before(startedAt) || req.VerifiedAt.After(now) || now.Sub(req.VerifiedAt) > 5*time.Minute {
		return out, ErrRemnawaveCutover
	}
	var importState, currentSHA string
	err = tx.QueryRow(ctx, `SELECT i.state,h.inventory_sha256 FROM remnawave_imports i JOIN remnawave_import_heads h ON h.import_id=i.id WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid FOR UPDATE OF i,h`, importID, req.TenantID).Scan(&importState, &currentSHA)
	if err != nil {
		return out, err
	}
	if importState != "activating" || currentSHA != inventorySHA {
		return out, ErrRemnawaveReview
	}
	var valid bool
	err = tx.QueryRow(ctx, `SELECT state='paused' AND import_id=$2::uuid AND inventory_sha256=$3 AND source_identity_reviewed AND activated_at IS NOT NULL FROM bot_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, req.TenantID, importID, inventorySHA).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrRemnawaveCutover
	}
	if err != nil {
		return out, err
	}
	if !valid {
		return out, ErrRemnawaveCutover
	}
	err = tx.QueryRow(ctx, `SELECT h.state='prepared' AND h.import_id=$2::uuid AND h.revision_id=$3::uuid AND r.inventory_sha256=$4 AND r.bundle_sha256=$5 FROM imported_subscription_profiles h JOIN imported_subscription_revisions r ON r.id=h.revision_id AND r.tenant_id=h.tenant_id WHERE h.tenant_id=$1::uuid FOR UPDATE OF h`, req.TenantID, importID, revision, inventorySHA, initial.BundleSHA256).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrRemnawaveCutover
	}
	if err != nil {
		return out, err
	}
	if !valid {
		return out, ErrRemnawaveCutover
	}
	for i, node := range req.Nodes {
		// Begin normalized the nodes in native ID order and kept that order in JSON.
		source := initial.Nodes[i]
		if source.NodeID != node.NodeID || node.GuardCommittedAt.Before(startedAt) || !node.GuardCommittedAt.Before(initial.RollbackDeadline) || node.GuardCommittedAt.After(req.VerifiedAt) {
			return out, ErrRemnawaveCutover
		}
		var desiredRaw []byte
		var agent string
		var ready bool
		err = tx.QueryRow(ctx, `SELECT ds.document,COALESCE(n.agent_version,''),
    n.runtime_core='xray' AND n.status='online' AND n.desired_generation=$3 AND n.applied_generation=$3
    AND n.last_seen_at>=now()-interval '90 seconds' AND h.healthy AND h.applied_generation=$3
    AND h.checked_at>=now()-interval '90 seconds' AND h.checked_at>=$4 AND h.core='xray'
    AND d.status='healthy' AND d.core_release_id=$5::uuid AND d.applied_core_version=r.version AND h.core_version=r.version
    AND r.approved AND NOT r.revoked AND xp.state='active' AND xp.import_id=$6::uuid
    AND xp.profile_sha256=$7 AND xp.adoption_sha256=$8
   FROM nodes n JOIN node_xray_profiles xp ON xp.node_id=n.id AND xp.tenant_id=n.tenant_id
   JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation
   JOIN deployments d ON d.node_id=n.id AND d.generation=n.desired_generation
   JOIN core_releases r ON r.id=d.core_release_id
   JOIN node_health h ON h.node_id=n.id
   WHERE n.id=$1::uuid AND n.tenant_id=$2::uuid FOR UPDATE OF n FOR SHARE OF r`, node.NodeID, req.TenantID, node.Generation, startedAt, initial.CoreReleaseID, importID, node.ProfileSHA256, source.MaterialSHA256).Scan(&desiredRaw, &agent, &ready)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrRemnawaveCutover
		}
		if err != nil {
			return out, err
		}
		if !ready || !xrayprofile.AgentCompatible(agent) {
			return out, ErrRemnawaveCutover
		}
		var desired model.DesiredState
		if json.Unmarshal(desiredRaw, &desired) != nil || desired.Generation != node.Generation || desired.XrayProfile == nil || desired.XrayProfile.SHA256 != node.ProfileSHA256 {
			return out, ErrXrayProfileIdentity
		}
		// Quotas/expiration can legitimately rebuild the runtime during verification.
		// Accept only a fresh proof for that exact generation and current native grants.
		if err = validateXrayProfileDesiredTx(ctx, tx, node.NodeID, desired, initial.CoreReleaseID); err != nil {
			return out, err
		}
		services := make([]string, 0, len(desired.Services))
		for _, service := range desired.Services {
			services = append(services, service.ID)
		}
		sort.Strings(services)
		if !reflect.DeepEqual(services, node.ServiceIDs) {
			return out, ErrRemnawaveCutover
		}
		err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM node_xray_profile_bindings b JOIN vpn_services s ON s.id=b.service_id AND s.node_id=b.node_id WHERE b.node_id=$1::uuid AND b.source_enabled<>s.enabled)`, node.NodeID).Scan(&valid)
		if err != nil {
			return out, err
		}
		if !valid {
			return out, ErrRemnawaveCutover
		}
	}
	// Publish all entry points in one commit; no partial active bot/public state.
	if _, err = tx.Exec(ctx, `UPDATE bot_profiles SET state='active' WHERE tenant_id=$1::uuid`, req.TenantID); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE imported_subscription_profiles SET state='active',activation_sha256=$2,activated_at=now() WHERE tenant_id=$1::uuid`, req.TenantID, proofSHA); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE remnawave_cutovers SET state='active',publication_sha256=$2,verified_at=$3 WHERE import_id=$1::uuid`, importID, proofSHA, req.VerifiedAt); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE remnawave_imports SET state='active' WHERE id=$1::uuid`, importID); err != nil {
		return out, err
	}
	actor, actorID := accessActor(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'remnawave.publication_committed',$2,$3,jsonb_build_object('import_id',$4::text,'publication_sha256',$5::text,'physical_proof','owner_attestation','evidence',$6::jsonb))`, req.TenantID, actor, actorID, importID, proofSHA, string(proofRaw)); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
