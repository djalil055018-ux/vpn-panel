package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"regexp"
	"vpn-platform/internal/model"
)

var ErrAgentFleetConflict = errors.New("agent fleet state conflict")
var ErrAgentFleetIneligible = errors.New("node is excluded from automatic agent updates")
var agentReleaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
var agentDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var agentFleetRouterName = regexp.MustCompile(`(?i)(router|роутер)`)

func agentFleetNodeNameEligible(name string) bool {
	return !agentFleetRouterName.MatchString(name)
}

// A registered OpenVPN runtime with no enabled OpenVPN service is intentionally
// quiesced. Agent-only releases must not stop or reprovision that runtime while
// the owner has disabled it.
const agentFleetOpenVPNEligible = `NOT (n.runtime_core='openvpn' AND NOT EXISTS (
	SELECT 1 FROM vpn_services s
	WHERE s.node_id=n.id AND s.tenant_id=n.tenant_id
	  AND s.enabled AND s.protocol='openvpn'
))`

// Avoid even evaluating the service-state predicate for router-labeled nodes.
// Router agent upgrades can interrupt router VPN runtimes; those updates require
// an explicit owner workflow outside the automatic fleet.
const agentFleetRouterNameExcluded = `n.name ~* '(router|роутер)'`
const agentFleetNodeEligible = `CASE WHEN ` + agentFleetRouterNameExcluded + ` THEN false ELSE (` + agentFleetOpenVPNEligible + `) END`

func lockAgentFleet(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103506,56)`)
	return err
}
func agentFleetAudit(ctx context.Context, tx pgx.Tx, event, id string) error {
	kind, actor := accessActor(ctx)
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload) VALUES($1,$2,$3,jsonb_build_object('run_id',$4::text))`, event, kind, actor, id)
	return err
}
func (p *Postgres) RegisterAgentRelease(ctx context.Context, r model.AgentRelease) error {
	if !adminOwnerAllowed(ctx) {
		return ErrAdminPermission
	}
	if !agentReleaseVersion.MatchString(r.Version) || !agentDigest.MatchString(r.BinarySHA256) || !agentDigest.MatchString(r.InstallerSHA256) {
		return ErrAgentFleetConflict
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return err
	}
	var valid bool
	if err = tx.QueryRow(ctx, `SELECT agent_version_rank($1)>=agent_version_rank('0.2.30')`, r.Version).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrAgentFleetConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_releases(version,binary_sha256,installer_sha256) VALUES($1,$2,$3) ON CONFLICT(version) DO NOTHING`, r.Version, r.BinarySHA256, r.InstallerSHA256)
	if err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `SELECT binary_sha256=$2 AND installer_sha256=$3 AND NOT revoked FROM agent_releases WHERE version=$1`, r.Version, r.BinarySHA256, r.InstallerSHA256).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrAgentFleetConflict
	}
	if err = agentFleetAudit(ctx, tx, "agent_release.registered", r.Version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const fleetHealthy = `n.status='online' AND n.agent_token_hash IS NOT NULL AND n.last_seen_at>now()-interval '90 seconds' AND h.checked_at BETWEEN now()-interval '90 seconds' AND now()+interval '10 seconds' AND h.healthy AND n.desired_generation=n.applied_generation AND h.applied_generation=n.applied_generation`

// Caller holds the global fleet lock. Only untouched queued work may move to a
// newer reviewed release. Claimed, failed and explicitly paused runs retain their
// execution/pause fence, regardless of how long an offline node has waited.
func supersedeIdleAgentFleet(ctx context.Context, tx pgx.Tx, target string) (bool, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT r.id::text FROM agent_fleet_runs r JOIN agent_releases v ON v.version=$1
 WHERE r.status='running' AND NOT v.revoked AND agent_version_rank(v.version)>agent_version_rank(r.target_version)
 AND NOT EXISTS(SELECT 1 FROM agent_fleet_jobs j WHERE j.run_id=r.id AND j.status IN ('claimed','failed'))`, target).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_fleet_jobs SET status='superseded',completed_at=now(),message='newer_release_selected'
 WHERE run_id=$1::uuid AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `UPDATE agent_fleet_runs SET status='completed',completed_at=now(),message='newer_release_selected' WHERE id=$1::uuid`, id)
	if err != nil {
		return false, err
	}
	return true, agentFleetAudit(ctx, tx, "agent_fleet.superseded", id)
}

// A reviewed version observed healthy on any node becomes the fleet target.
// Queued offline nodes wait; uncertain claimed jobs retain the single global slot.
func reconcileAgentFleet(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `UPDATE agent_fleet_runs r SET status='paused',message='updater_result_overdue' WHERE r.status='running' AND EXISTS(SELECT 1 FROM agent_fleet_jobs j WHERE j.run_id=r.id AND j.status='claimed' AND j.claimed_at<now()-interval '10 minutes')`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_fleet_runs r SET status='paused',message='release_revoked' FROM agent_releases v WHERE r.target_version=v.version AND v.revoked AND r.status='running'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_fleet_jobs j SET status=CASE WHEN n.agent_version=r.target_version THEN 'already_current' ELSE 'superseded' END,completed_at=now(),message='healthy_version_observed' FROM agent_fleet_runs r,nodes n,node_health h WHERE j.run_id=r.id AND j.node_id=n.id AND h.node_id=n.id AND j.status='queued' AND agent_version_rank(n.agent_version)>=agent_version_rank(r.target_version) AND `+fleetHealthy); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_fleet_runs r SET status='completed',completed_at=now() WHERE r.status='running' AND NOT EXISTS(SELECT 1 FROM agent_fleet_jobs j WHERE j.run_id=r.id AND j.status IN ('queued','claimed','failed'))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_fleet_policy p SET target_version=v.version,updated_at=now() FROM (SELECT a.version FROM agent_releases a JOIN nodes n ON n.agent_version=a.version JOIN node_health h ON h.node_id=n.id WHERE NOT a.revoked AND `+fleetHealthy+` ORDER BY agent_version_rank(a.version) DESC LIMIT 1) v WHERE p.auto_spread AND (p.target_version IS NULL OR agent_version_rank(v.version)>agent_version_rank(p.target_version))`); err != nil {
		return err
	}
	var target string
	err := tx.QueryRow(ctx, `SELECT p.target_version FROM agent_fleet_policy p JOIN agent_releases v ON v.version=p.target_version WHERE p.auto_spread AND NOT v.revoked`).Scan(&target)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		if _, err = supersedeIdleAgentFleet(ctx, tx, target); err != nil {
			return err
		}
	}
	err = tx.QueryRow(ctx, `SELECT p.target_version FROM agent_fleet_policy p JOIN agent_releases v ON v.version=p.target_version WHERE p.auto_spread AND NOT v.revoked AND NOT EXISTS(SELECT 1 FROM agent_fleet_runs WHERE status IN ('running','paused')) AND EXISTS(SELECT 1 FROM nodes n WHERE n.agent_token_hash IS NOT NULL AND (agent_version_rank(n.agent_version)<agent_version_rank(p.target_version) OR agent_version_rank(n.agent_version) IS NULL) AND `+agentFleetNodeEligible+`)`).Scan(&target)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var id string
	if err = tx.QueryRow(ctx, `INSERT INTO agent_fleet_runs(target_version,origin) VALUES($1,'observed') RETURNING id::text`, target).Scan(&id); err != nil {
		return err
	}
	if err = addAgentFleetJobs(ctx, tx, id, target); err != nil {
		return err
	}
	return agentFleetAudit(ctx, tx, "agent_fleet.propagated", id)
}
func addAgentFleetJobs(ctx context.Context, tx pgx.Tx, id, target string) error {
	_, err := tx.Exec(ctx, `INSERT INTO agent_fleet_jobs(run_id,node_id,from_version) SELECT $1::uuid,n.id,coalesce(n.agent_version,'') FROM nodes n WHERE n.agent_token_hash IS NOT NULL AND n.status<>'decommissioning' AND (agent_version_rank(n.agent_version)<agent_version_rank($2) OR agent_version_rank(n.agent_version) IS NULL) AND `+agentFleetNodeEligible+` ON CONFLICT(run_id,node_id) DO NOTHING`, id, target)
	return err
}
func (p *Postgres) ReconcileAgentFleet(ctx context.Context) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return err
	}
	if err = reconcileAgentFleet(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (p *Postgres) StartAgentFleet(ctx context.Context, nodeID, requestKey string) (string, error) {
	if !adminOwnerAllowed(ctx) {
		return "", ErrAdminPermission
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return "", err
	}
	var id, origin string
	err = tx.QueryRow(ctx, `SELECT id::text,coalesce(origin_node_id::text,'') FROM agent_fleet_runs WHERE request_key=$1::uuid`, requestKey).Scan(&id, &origin)
	if err == nil {
		if origin != nodeID {
			return "", ErrAgentFleetConflict
		}
		return id, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var registered, eligible bool
	if err = tx.QueryRow(ctx, `SELECT agent_token_hash IS NOT NULL AND status<>'decommissioning', `+agentFleetNodeEligible+` FROM nodes n WHERE n.id=$1::uuid`, nodeID).Scan(&registered, &eligible); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	if !registered {
		return "", ErrAgentFleetConflict
	}
	if !eligible {
		return "", ErrAgentFleetIneligible
	}
	var target string
	if err = tx.QueryRow(ctx, `SELECT version FROM agent_releases WHERE NOT revoked ORDER BY agent_version_rank(version) DESC LIMIT 1`).Scan(&target); err != nil {
		return "", err
	}
	var runningTarget string
	err = tx.QueryRow(ctx, `SELECT id::text,target_version FROM agent_fleet_runs WHERE status IN ('running','paused')`).Scan(&id, &runningTarget)
	if err == nil {
		if target == runningTarget {
			return id, tx.Commit(ctx)
		}
		superseded, e := supersedeIdleAgentFleet(ctx, tx, target)
		if e != nil {
			return "", e
		}
		if !superseded {
			return "", ErrAgentFleetConflict
		}
		err = pgx.ErrNoRows
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if err = tx.QueryRow(ctx, `INSERT INTO agent_fleet_runs(request_key,target_version,origin_node_id,priority_node_id,origin) VALUES($1::uuid,$2,$3::uuid,$3::uuid,'manual') RETURNING id::text`, requestKey, target, nodeID).Scan(&id); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_fleet_policy SET target_version=$1,updated_at=now() WHERE target_version IS NULL OR agent_version_rank(target_version)<agent_version_rank($1)`, target); err != nil {
		return "", err
	}
	if err = addAgentFleetJobs(ctx, tx, id, target); err != nil {
		return "", err
	}
	if err = agentFleetAudit(ctx, tx, "agent_fleet.started", id); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (p *Postgres) ClaimAgentUpdate(ctx context.Context, nodeID string) (*model.AgentUpdateAssignment, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return nil, err
	}
	var retired bool
	if err = tx.QueryRow(ctx, `SELECT status='retired' FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&retired); err != nil {
		return nil, err
	}
	if retired {
		return nil, ErrNodeRetired
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_updaters(node_id,version) VALUES($1::uuid,'0.1.0') ON CONFLICT(node_id) DO UPDATE SET version=EXCLUDED.version,last_seen_at=now()`, nodeID); err != nil {
		return nil, err
	}
	if err = reconcileAgentFleet(ctx, tx); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, nodeID); err != nil {
		return nil, err
	}
	// Return an existing claim even when paused, so a restarted updater can report
	// its durable result. It must not run the installer twice after receipt loss.
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE node_id=$1::uuid AND status='claimed')`, nodeID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		_, err = tx.Exec(ctx, `UPDATE agent_fleet_jobs j SET status='claimed',claim_id=gen_random_uuid(),claimed_at=now(),message='' FROM agent_fleet_runs r,agent_releases v,nodes n,node_health h WHERE j.node_id=$1::uuid AND n.id=j.node_id AND h.node_id=n.id AND j.run_id=r.id AND r.target_version=v.version AND r.status='running' AND NOT v.revoked AND j.status='queued' AND NOT EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE status='claimed') AND NOT EXISTS(SELECT 1 FROM agent_fleet_jobs priority WHERE priority.run_id=r.id AND priority.node_id=r.priority_node_id AND priority.status='queued' AND priority.id<>j.id) AND n.os_name='ubuntu' AND n.os_version='24.04' AND n.architecture='amd64' AND agent_version_rank(n.agent_version)<agent_version_rank(r.target_version) AND `+fleetHealthy, nodeID)
		if err != nil {
			return nil, err
		}
	}
	var a model.AgentUpdateAssignment
	err = tx.QueryRow(ctx, `SELECT j.id::text,j.run_id::text,j.node_id::text,j.claim_id::text,j.from_version,r.status='running' AND NOT v.revoked AND j.claimed_at>now()-interval '10 minutes',r.target_version,v.binary_sha256,v.installer_sha256 FROM agent_fleet_jobs j JOIN agent_fleet_runs r ON r.id=j.run_id JOIN agent_releases v ON v.version=r.target_version WHERE j.node_id=$1::uuid AND j.status='claimed'`, nodeID).Scan(&a.JobID, &a.RunID, &a.NodeID, &a.ClaimID, &a.FromVersion, &a.CanExecute, &a.Release.Version, &a.Release.BinarySHA256, &a.Release.InstallerSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	return &a, tx.Commit(ctx)
}

func (p *Postgres) ReportAgentUpdate(ctx context.Context, nodeID, jobID string, r model.AgentUpdateReport) error {
	if r.Status != "succeeded" && r.Status != "failed" {
		return ErrAgentFleetConflict
	}
	// Fixed result codes keep installer logs, tokens and filesystem paths out of
	// browser responses and audit records.
	allowed := map[string]bool{"ready": true, "preflight_failed": true, "download_failed": true, "installer_failed": true, "interrupted": true, "receipt_conflict": true, "release_revoked": true}
	if !allowed[r.Code] || (r.Status == "succeeded" && r.Code != "ready") {
		return ErrAgentFleetConflict
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return err
	}
	var status, claim, runID, version, digest, savedDigest, code string
	err = tx.QueryRow(ctx, `SELECT j.status,coalesce(j.claim_id::text,''),j.run_id::text,f.target_version,v.binary_sha256,coalesce(j.binary_sha256,''),j.message FROM agent_fleet_jobs j JOIN agent_fleet_runs f ON f.id=j.run_id JOIN agent_releases v ON v.version=f.target_version WHERE j.id=$1::uuid AND j.node_id=$2::uuid`, jobID, nodeID).Scan(&status, &claim, &runID, &version, &digest, &savedDigest, &code)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if claim != r.ClaimID || claim == "" {
		return ErrAgentFleetConflict
	}
	if status == "succeeded" || status == "failed" {
		if status != r.Status || savedDigest != r.BinarySHA256 || code != r.Code {
			return ErrAgentFleetConflict
		}
		return tx.Commit(ctx)
	}
	if status != "claimed" {
		return ErrAgentFleetConflict
	}
	if r.Status == "succeeded" {
		if r.BinarySHA256 != digest {
			return ErrAgentFleetConflict
		}
		var healthy bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_health h ON h.node_id=n.id JOIN agent_fleet_jobs j ON j.node_id=n.id WHERE n.id=$1::uuid AND j.id=$2::uuid AND n.agent_version=$3 AND n.last_seen_at>=j.claimed_at AND h.checked_at>=j.claimed_at AND `+fleetHealthy+`)`, nodeID, jobID, version).Scan(&healthy); err != nil {
			return err
		}
		if !healthy {
			return ErrAgentFleetConflict
		}
	} else if r.BinarySHA256 != "" && !agentDigest.MatchString(r.BinarySHA256) {
		return ErrAgentFleetConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_fleet_jobs SET status=$2,completed_at=now(),message=$3,binary_sha256=$4 WHERE id=$1::uuid`, jobID, r.Status, r.Code, r.BinarySHA256); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO agent_fleet_attempts(job_id,claim_id,result) SELECT id,claim_id,to_jsonb(j) FROM agent_fleet_jobs j WHERE id=$1::uuid`, jobID); err != nil {
		return err
	}
	if r.Status == "failed" {
		if _, err = tx.Exec(ctx, `UPDATE agent_fleet_runs SET status='paused',message='node_update_failed' WHERE id=$1::uuid`, runID); err != nil {
			return err
		}
	}
	if err = agentFleetAudit(ctx, tx, "agent_fleet.node_"+r.Status, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) RetryAgentUpdate(ctx context.Context, jobID string) error {
	if !adminOwnerAllowed(ctx) {
		return ErrAdminPermission
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return err
	}
	var runID string
	err = tx.QueryRow(ctx, `SELECT j.run_id::text FROM agent_fleet_jobs j JOIN agent_fleet_runs r ON r.id=j.run_id JOIN agent_releases v ON v.version=r.target_version JOIN nodes n ON n.id=j.node_id JOIN node_health h ON h.node_id=n.id WHERE j.id=$1::uuid AND j.status='failed' AND r.status='paused' AND NOT v.revoked AND NOT EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE status='claimed') AND `+fleetHealthy, jobID).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAgentFleetConflict
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_fleet_jobs SET status='queued',claim_id=NULL,claimed_at=NULL,completed_at=NULL,message='',binary_sha256=NULL WHERE id=$1::uuid`, jobID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_fleet_runs SET status='running',message='',priority_node_id=(SELECT node_id FROM agent_fleet_jobs WHERE id=$2::uuid) WHERE id=$1::uuid`, runID, jobID); err != nil {
		return err
	}
	if err = agentFleetAudit(ctx, tx, "agent_fleet.retry_requested", runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) AgentFleetStatus(ctx context.Context) (json.RawMessage, error) {
	if _, ok := TenantPrincipal(ctx); ok {
		return nil, ErrAdminPermission
	}
	var raw []byte
	query := `SELECT jsonb_build_object(
 'policy',(SELECT to_jsonb(p)-'singleton' FROM agent_fleet_policy p),
 'releases',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY agent_version_rank(v.version) DESC),'[]') FROM agent_releases v),
 'runs',(SELECT coalesce(jsonb_agg(to_jsonb(r)||jsonb_build_object('jobs',(SELECT coalesce(jsonb_agg(to_jsonb(j)-'claim_id' ORDER BY n.name),'[]') FROM agent_fleet_jobs j JOIN nodes n ON n.id=j.node_id WHERE j.run_id=r.id)) ORDER BY r.created_at DESC),'[]') FROM (SELECT * FROM agent_fleet_runs ORDER BY created_at DESC LIMIT 20) r),
	'nodes',(SELECT coalesce(jsonb_agg(jsonb_build_object('id',n.id,'name',n.name,'agent_version',n.agent_version,'registered',n.agent_token_hash IS NOT NULL,'online',coalesce(n.last_seen_at>now()-interval '90 seconds',false),'updater_online',coalesce(u.last_seen_at>now()-interval '90 seconds',false),'updater_version',u.version,'platform_supported',coalesce(n.os_name='ubuntu' AND n.os_version='24.04' AND n.architecture='amd64',false),'agent_update_eligible',` + agentFleetNodeEligible + `) ORDER BY n.name),'[]') FROM nodes n LEFT JOIN agent_updaters u ON u.node_id=n.id WHERE n.status<>'retired'))`
	err := p.Pool.QueryRow(ctx, query).Scan(&raw)
	return json.RawMessage(raw), err
}

func (p *Postgres) SetAgentFleetPaused(ctx context.Context, runID string, paused bool) error {
	if !adminOwnerAllowed(ctx) {
		return ErrAdminPermission
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAgentFleet(ctx, tx); err != nil {
		return err
	}
	var status string
	if err = tx.QueryRow(ctx, `SELECT status FROM agent_fleet_runs WHERE id=$1::uuid`, runID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if status == "completed" {
		return ErrAgentFleetConflict
	}
	if !paused {
		var blocked bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE run_id=$1::uuid AND status IN ('claimed','failed')) OR EXISTS(SELECT 1 FROM agent_fleet_runs r JOIN agent_releases v ON v.version=r.target_version WHERE r.id=$1::uuid AND v.revoked)`, runID).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return ErrAgentFleetConflict
		}
	}
	next := "running"
	if paused {
		next = "paused"
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_fleet_runs SET status=$2,message=CASE WHEN $2='paused' THEN 'paused_by_owner' ELSE '' END WHERE id=$1::uuid`, runID, next); err != nil {
		return err
	}
	if err = agentFleetAudit(ctx, tx, "agent_fleet."+next, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
