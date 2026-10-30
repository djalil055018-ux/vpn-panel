package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

func (p *Postgres) NodeRuntimeStatus(
	ctx context.Context,
	nodeID string,
) (model.NodeRuntimeStatus, error) {
	var result model.NodeRuntimeStatus

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			n.id::text,
			n.status,
			(nh.node_id IS NOT NULL),
			COALESCE(nh.healthy, false) AND n.status<>'retired',
			n.desired_generation,
			n.applied_generation,
			COALESCE(nh.applied_generation, 0),
			COALESCE(nh.core_version, ''),
			COALESCE(
				nh.last_known_good_core_version,
				''
			),
			COALESCE(nh.snapshot_count, 0),
			COALESCE(nh.latest_snapshot_id, ''),
			COALESCE(nh.rollback_ready, false) AND n.status<>'retired',
			nh.checked_at
		FROM nodes n
		LEFT JOIN node_health nh
			ON nh.node_id = n.id
		WHERE n.id = $1::uuid
		`,
		nodeID,
	).Scan(
		&result.NodeID,
		&result.NodeStatus,
		&result.HealthPresent,
		&result.Healthy,
		&result.DesiredGeneration,
		&result.AppliedGeneration,
		&result.HealthAppliedGeneration,
		&result.CurrentCoreVersion,
		&result.LastKnownGoodCoreVersion,
		&result.SnapshotCount,
		&result.LatestSnapshotID,
		&result.RollbackReady,
		&result.CheckedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.NodeRuntimeStatus{},
			ErrNotFound
	}

	if err != nil {
		return model.NodeRuntimeStatus{},
			err
	}

	return result, nil
}
