package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

var ErrReviewedXrayUpdate = errors.New("reviewed Xray update unavailable")
var reviewedXraySlots = make(chan struct{}, 4)

// StartReviewedXrayUpdate composes the existing policy, plan, approval and
// execution checks. A request key persists in the plan transaction, so a lost
// response resumes that exact plan instead of creating another deployment.
func (p *Postgres) StartReviewedXrayUpdate(ctx context.Context, nodeID, releaseID, requestKey string, acceptPrerelease bool) (model.RolloutPlan, error) {
	empty := model.RolloutPlan{}
	if _, ok := TenantPrincipal(ctx); ok {
		return empty, ErrAdminPermission
	}
	if principal, ok := AdminPrincipal(ctx); ok && principal.Account.Role != "owner" && principal.Account.Role != "admin" {
		return empty, ErrAdminPermission
	}
	select {
	case reviewedXraySlots <- struct{}{}:
	case <-ctx.Done():
		return empty, ctx.Err()
	}
	defer func() { <-reviewedXraySlots }()
	// Dedicated lock connections cannot exhaust the normal pool while the
	// composed operations acquire their own transactional connections.
	connection, err := pgx.ConnectConfig(ctx, p.Pool.Config().ConnConfig.Copy())
	if err != nil {
		return empty, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = connection.Close(cleanup)
	}()
	// Session locks serialize retries and competing buttons for this node without
	// holding a node row lock while existing store methods open their transactions.
	keys := []string{"reviewed-xray-request/" + requestKey, "reviewed-xray-node/" + nodeID}
	locked := []string{}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for i := len(locked) - 1; i >= 0; i-- {
			if _, e := connection.Exec(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, locked[i]); e != nil {
				_ = connection.Close(cleanup)
				break
			}
		}
	}()
	for _, key := range keys {
		if _, err = connection.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, key); err != nil {
			return empty, err
		}
		locked = append(locked, key)
	}
	var planID, priorNode, priorRelease string
	err = connection.QueryRow(ctx, `SELECT id::text,node_id::text,coalesce(target_core_release_id::text,'') FROM rollout_plans WHERE request_key=$1::uuid`, requestKey).Scan(&planID, &priorNode, &priorRelease)
	if err == nil && (priorNode != nodeID || priorRelease != releaseID) {
		return empty, ErrReviewedXrayUpdate
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return empty, err
	}
	var plan model.RolloutPlan
	if planID != "" {
		plan, err = p.GetRolloutPlan(ctx, planID)
		if err != nil {
			return empty, err
		}
		if plan.Status == "executed" {
			return plan, nil
		}
	} else {
		var releaseVersion string
		var prerelease bool
		err = connection.QueryRow(ctx, `SELECT v.version,v.upstream_prerelease FROM core_releases v JOIN nodes n ON n.id=$2::uuid JOIN node_health h ON h.node_id=n.id WHERE v.id=$1::uuid AND v.core_type='xray' AND n.runtime_core='xray' AND h.core='xray' AND v.os='linux' AND v.architecture=n.architecture AND v.approved AND NOT v.revoked AND `+fleetHealthy, releaseID, nodeID).Scan(&releaseVersion, &prerelease)
		if errors.Is(err, pgx.ErrNoRows) {
			return empty, ErrReviewedXrayUpdate
		}
		if err != nil {
			return empty, err
		}
		if prerelease && !acceptPrerelease {
			return empty, ErrReviewedXrayUpdate
		}
		var current string
		if err = connection.QueryRow(ctx, `SELECT core_version FROM node_health WHERE node_id=$1::uuid`, nodeID).Scan(&current); err != nil {
			return empty, err
		}
		if current == "" || compareCoreVersions(releaseVersion, current) <= 0 {
			return empty, ErrReviewedXrayUpdate
		}
		// An Agent installation owns the runtime while it is replacing the process.
		var agentBusy bool
		if err = connection.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE node_id=$1::uuid AND status='claimed')`, nodeID).Scan(&agentBusy); err != nil {
			return empty, err
		}
		if agentBusy {
			return empty, ErrReviewedXrayUpdate
		}
		if _, _, err = p.SetCoreUpdatePolicy(ctx, nodeID, "xray", "pinned", releaseVersion); err != nil {
			return empty, err
		}
		plan, err = p.createCoreRolloutPlan(ctx, nodeID, "xray", requestKey)
		if err != nil {
			return empty, err
		}
	}
	if plan.TargetCoreReleaseID != releaseID || plan.CoreType != "xray" {
		return empty, ErrReviewedXrayUpdate
	}
	if plan.Status == "planned" {
		plan, err = p.ApproveRolloutPlan(ctx, plan.ID)
		if err != nil {
			return empty, err
		}
	}
	if plan.Status != "approved" {
		return empty, ErrReviewedXrayUpdate
	}
	plan, _, err = p.ExecuteRolloutPlan(ctx, plan.ID)
	return plan, err
}
