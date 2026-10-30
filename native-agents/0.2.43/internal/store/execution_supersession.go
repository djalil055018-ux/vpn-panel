package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

// A newer desired generation does not prove that the previous physical worker
// stopped. Keep its exact owner/lease proof and request normal fencing; never
// release an active lease merely because its generation was superseded.
func (p *Postgres) fenceSupersededExecution(ctx context.Context, nodeID string) error {
	var e model.ExecutionAssignment
	err := p.Pool.QueryRow(ctx, `SELECT l.deployment_id::text,l.generation,l.execution_id::text,l.execution_epoch
 FROM deployment_execution_leases l JOIN nodes n ON n.id=l.node_id JOIN deployments d ON d.id=l.deployment_id
 WHERE l.node_id=$1::uuid AND l.state='active' AND l.generation<n.desired_generation
 AND l.generation>n.applied_generation AND d.status IN ('pending','applying')
 AND NOT EXISTS(SELECT 1 FROM execution_fence_requests f WHERE f.deployment_id=l.deployment_id AND f.state='requested')
 ORDER BY l.generation LIMIT 1`, nodeID).Scan(&e.DeploymentID, &e.Generation, &e.ExecutionID, &e.ExecutionEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = p.CreateExecutionFenceRequest(ctx, nodeID, e, "superseded by newer desired generation")
	// The owner may finish or another request may win between these transactions.
	// The assignment query still gives any outstanding fence priority.
	if errors.Is(err, ErrExecutionFenceNotRequestable) || errors.Is(err, ErrExecutionFenceConflict) {
		return nil
	}
	return err
}
