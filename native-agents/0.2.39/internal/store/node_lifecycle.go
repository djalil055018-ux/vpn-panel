package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

var ErrNodeAlreadyRegistered = errors.New("node already registered")

type nodeLifecycleFacts struct {
	Node model.Node

	Registered        bool
	BootstrapConsumed bool

	HealthPresent           bool
	HealthHealthy           bool
	HealthAppliedGeneration int64
	HealthCoreVersion       string
	HealthLKGVersion        string
	SnapshotCount           int64
	LatestSnapshotID        string
	RollbackReady           bool
	HealthCheckedAt         *time.Time

	LatestDeploymentGeneration int64
	LatestDeploymentStatus     string
	LatestDeploymentError      string

	ActiveRecovery bool
}

func (p *Postgres) loadNodeLifecycleFacts(
	ctx context.Context,
	nodeID string,
) (nodeLifecycleFacts, error) {
	var facts nodeLifecycleFacts

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			n.id::text,
			n.tenant_id::text,
			n.name,
			n.status,
			COALESCE(n.agent_version, ''),
			COALESCE(n.os_name, ''),
			COALESCE(n.os_version, ''),
			COALESCE(n.architecture, ''),
			n.desired_generation,
			n.applied_generation,
			n.last_seen_at,
			n.created_at,
			n.runtime_core,

			(n.agent_token_hash IS NOT NULL),
			(n.bootstrap_used_at IS NOT NULL),

			(nh.node_id IS NOT NULL),
			COALESCE(nh.healthy, false),
			COALESCE(nh.applied_generation, 0),
			COALESCE(nh.core_version, ''),
			COALESCE(
				nh.last_known_good_core_version,
				''
			),
			COALESCE(nh.snapshot_count, 0),
			COALESCE(nh.latest_snapshot_id, ''),
			COALESCE(nh.rollback_ready, false),
			nh.checked_at,

			COALESCE(ld.generation, 0),
			COALESCE(ld.status, ''),
			COALESCE(ld.error_message, ''),

			COALESCE(ar.active, false)

		FROM nodes n

		LEFT JOIN node_health nh
			ON nh.node_id = n.id

		LEFT JOIN LATERAL (
			SELECT
				d.generation,
				d.status,
				d.error_message
			FROM deployments d
			WHERE d.node_id = n.id
			ORDER BY d.generation DESC
			LIMIT 1
		) ld ON true

		LEFT JOIN LATERAL (
			SELECT true AS active
			FROM recovery_attempts ra
			LEFT JOIN deployments rd
				ON rd.id = ra.deployment_id
			WHERE ra.node_id = n.id
			  AND (
				ra.status IN (
					'planned',
					'approved'
				)
				OR (
					ra.status = 'executed'
					AND rd.status IN (
						'pending',
						'applying'
					)
				)
			  )
			ORDER BY ra.created_at DESC
			LIMIT 1
		) ar ON true

		WHERE n.id = $1::uuid
		`,
		nodeID,
	).Scan(
		&facts.Node.ID,
		&facts.Node.TenantID,
		&facts.Node.Name,
		&facts.Node.Status,
		&facts.Node.AgentVersion,
		&facts.Node.OSName,
		&facts.Node.OSVersion,
		&facts.Node.Architecture,
		&facts.Node.DesiredGeneration,
		&facts.Node.AppliedGeneration,
		&facts.Node.LastSeenAt,
		&facts.Node.CreatedAt,
		&facts.Node.RuntimeCore,

		&facts.Registered,
		&facts.BootstrapConsumed,

		&facts.HealthPresent,
		&facts.HealthHealthy,
		&facts.HealthAppliedGeneration,
		&facts.HealthCoreVersion,
		&facts.HealthLKGVersion,
		&facts.SnapshotCount,
		&facts.LatestSnapshotID,
		&facts.RollbackReady,
		&facts.HealthCheckedAt,

		&facts.LatestDeploymentGeneration,
		&facts.LatestDeploymentStatus,
		&facts.LatestDeploymentError,

		&facts.ActiveRecovery,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nodeLifecycleFacts{},
			ErrNotFound
	}

	if err != nil {
		return nodeLifecycleFacts{}, err
	}

	return facts, nil
}

func deriveNodeLifecycle(
	facts nodeLifecycleFacts,
	now time.Time,
) model.NodeLifecycleStatus {
	online :=
		facts.Node.LastSeenAt != nil &&
			!facts.Node.LastSeenAt.Before(
				now.Add(
					-nodeOnlineWindow,
				),
			)

	healthFresh :=
		facts.HealthCheckedAt != nil &&
			!facts.HealthCheckedAt.Before(
				now.Add(
					-nodeOnlineWindow,
				),
			)

	state := "degraded"

	switch {
	case facts.Node.Status == "decommissioning":
		state = "decommissioning"
	case facts.Node.Status == "retired":
		state = "retired"
		online = false
		healthFresh = false
	case !facts.Registered ||
		facts.Node.LastSeenAt == nil:
		state = "provisioning"

	case !online:
		state = "offline"

	case facts.ActiveRecovery:
		state = "recovering"

	case facts.Node.DesiredGeneration !=
		facts.Node.AppliedGeneration ||
		facts.LatestDeploymentStatus == "pending" ||
		facts.LatestDeploymentStatus == "applying":
		state = "updating"

	case !facts.HealthPresent ||
		!healthFresh ||
		!facts.HealthHealthy:
		state = "degraded"

	default:
		state = "online"
	}

	return model.NodeLifecycleStatus{
		NodeID:            facts.Node.ID,
		State:             state,
		Online:            online,
		Registered:        facts.Registered,
		BootstrapConsumed: facts.BootstrapConsumed,
		AgentVersion:      facts.Node.AgentVersion,
		RuntimeCore:       facts.Node.RuntimeCore,
		OSName:            facts.Node.OSName,
		OSVersion:         facts.Node.OSVersion,
		Architecture:      facts.Node.Architecture,

		DesiredGeneration: facts.Node.DesiredGeneration,

		AppliedGeneration: facts.Node.AppliedGeneration,

		GenerationDrift: facts.Node.DesiredGeneration -
			facts.Node.AppliedGeneration,

		HealthPresent: facts.HealthPresent,

		HealthFresh: healthFresh,

		Healthy: facts.HealthPresent &&
			healthFresh &&
			facts.HealthHealthy,

		CurrentCoreVersion: facts.HealthCoreVersion,

		LastKnownGoodCoreVersion: facts.HealthLKGVersion,

		RollbackReady: facts.RollbackReady && facts.Node.Status != "retired",

		LatestDeploymentGeneration: facts.LatestDeploymentGeneration,

		LatestDeploymentStatus: facts.LatestDeploymentStatus,

		ActiveRecovery: facts.ActiveRecovery,

		LastSeenAt: facts.Node.LastSeenAt,

		HealthCheckedAt: facts.HealthCheckedAt,
	}
}

func runtimeStatusFromLifecycleFacts(
	facts nodeLifecycleFacts,
) model.NodeRuntimeStatus {
	return model.NodeRuntimeStatus{
		NodeID: facts.Node.ID,

		NodeStatus: facts.Node.Status,

		HealthPresent: facts.HealthPresent,

		Healthy: facts.HealthHealthy && facts.Node.Status != "retired",

		DesiredGeneration: facts.Node.DesiredGeneration,

		AppliedGeneration: facts.Node.AppliedGeneration,

		HealthAppliedGeneration: facts.HealthAppliedGeneration,

		CurrentCoreVersion: facts.HealthCoreVersion,

		LastKnownGoodCoreVersion: facts.HealthLKGVersion,

		SnapshotCount: facts.SnapshotCount,

		LatestSnapshotID: facts.LatestSnapshotID,

		RollbackReady: facts.RollbackReady && facts.Node.Status != "retired",

		CheckedAt: facts.HealthCheckedAt,
	}
}

func (p *Postgres) NodeDetail(
	ctx context.Context,
	nodeID string,
	now time.Time,
) (model.NodeDetail, error) {
	facts, err :=
		p.loadNodeLifecycleFacts(
			ctx,
			nodeID,
		)
	if err != nil {
		return model.NodeDetail{}, err
	}

	return model.NodeDetail{
		Node: facts.Node,

		Runtime: runtimeStatusFromLifecycleFacts(
			facts,
		),

		Lifecycle: deriveNodeLifecycle(
			facts,
			now,
		),
	}, nil
}

func (p *Postgres) NodeLifecycle(
	ctx context.Context,
	nodeID string,
	now time.Time,
) (model.NodeLifecycleStatus, error) {
	facts, err :=
		p.loadNodeLifecycleFacts(
			ctx,
			nodeID,
		)
	if err != nil {
		return model.NodeLifecycleStatus{},
			err
	}

	return deriveNodeLifecycle(
		facts,
		now,
	), nil
}

func buildNodeDiagnostics(
	facts nodeLifecycleFacts,
	now time.Time,
) model.NodeDiagnostics {
	lifecycle :=
		deriveNodeLifecycle(
			facts,
			now,
		)

	checks :=
		make(
			[]model.DiagnosticCheck,
			0,
			6,
		)

	add := func(
		code string,
		status string,
		message string,
	) {
		checks =
			append(
				checks,
				model.DiagnosticCheck{
					Code:    code,
					Status:  status,
					Message: message,
				},
			)
	}

	if lifecycle.State == "retired" {
		return model.NodeDiagnostics{NodeID: facts.Node.ID, LifecycleState: "retired", Overall: "ok", Checks: []model.DiagnosticCheck{{Code: "node_retired", Status: "ok", Message: "node deleted; history retained and agent credentials revoked"}}, GeneratedAt: now}
	}
	if lifecycle.Registered {
		add(
			"agent_registration",
			"ok",
			"agent registered",
		)
	} else {
		add(
			"agent_registration",
			"error",
			"agent is not registered",
		)
	}

	if lifecycle.Online {
		add(
			"heartbeat",
			"ok",
			"agent heartbeat is fresh",
		)
	} else {
		add(
			"heartbeat",
			"error",
			"agent heartbeat is missing or stale",
		)
	}

	switch {
	case !facts.HealthPresent:
		add(
			"health",
			"warning",
			"health report is missing",
		)

	case !lifecycle.HealthFresh:
		add(
			"health",
			"warning",
			"health report is stale",
		)

	case !facts.HealthHealthy:
		add(
			"health",
			"error",
			"node reports unhealthy",
		)

	default:
		add(
			"health",
			"ok",
			"node reports healthy",
		)
	}

	if facts.Node.DesiredGeneration ==
		facts.Node.AppliedGeneration {

		add(
			"generation",
			"ok",
			fmt.Sprintf(
				"desired and applied generation are %d",
				facts.Node.AppliedGeneration,
			),
		)
	} else {
		add(
			"generation",
			"warning",
			fmt.Sprintf(
				"desired=%d applied=%d",
				facts.Node.DesiredGeneration,
				facts.Node.AppliedGeneration,
			),
		)
	}

	if facts.HealthCoreVersion != "" {
		add(
			"core",
			"ok",
			"current core "+facts.HealthCoreVersion,
		)
	} else {
		add(
			"core",
			"warning",
			"current core version unavailable",
		)
	}

	if facts.RollbackReady {
		add(
			"rollback",
			"ok",
			"rollback snapshot is available",
		)
	} else {
		add(
			"rollback",
			"warning",
			"no validated rollback snapshot available",
		)
	}

	if facts.LatestDeploymentStatus != "" {
		status := "ok"

		if facts.LatestDeploymentStatus == "failed" ||
			facts.LatestDeploymentStatus ==
				"rolled_back" {

			status = "warning"
		}

		add(
			"latest_deployment",
			status,
			fmt.Sprintf(
				"generation=%d status=%s",
				facts.LatestDeploymentGeneration,
				facts.LatestDeploymentStatus,
			),
		)
	}

	overall := "ok"

	for _, check := range checks {
		if check.Status == "error" {
			overall = "error"
			break
		}

		if check.Status == "warning" &&
			overall == "ok" {

			overall = "warning"
		}
	}

	return model.NodeDiagnostics{
		NodeID: facts.Node.ID,

		LifecycleState: lifecycle.State,

		Overall: overall,

		Checks: checks,

		GeneratedAt: now,
	}
}

func (p *Postgres) NodeDiagnostics(
	ctx context.Context,
	nodeID string,
	now time.Time,
) (model.NodeDiagnostics, error) {
	facts, err :=
		p.loadNodeLifecycleFacts(
			ctx,
			nodeID,
		)
	if err != nil {
		return model.NodeDiagnostics{}, err
	}

	return buildNodeDiagnostics(
		facts,
		now,
	), nil
}
