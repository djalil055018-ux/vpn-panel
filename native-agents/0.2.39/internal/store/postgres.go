package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-platform/internal/model"
)

var ErrNotFound = errors.New("not found")

type Postgres struct {
	Pool *pgxpool.Pool
}

func NewPostgres(
	ctx context.Context,
	dsn string,
) (*Postgres, error) {

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return &Postgres{
		Pool: pool,
	}, nil
}

func (p *Postgres) Close() {
	p.Pool.Close()
}

func (p *Postgres) CreateTenant(
	ctx context.Context,
	name string,
) (model.Tenant, error) {

	var tenant model.Tenant

	err := p.Pool.QueryRow(
		ctx,
		`
		INSERT INTO tenants(name)
		VALUES ($1)
		RETURNING
			id::text,
			name,
			created_at
		`,
		name,
	).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.CreatedAt,
	)

	return tenant, err
}

func (p *Postgres) ListTenants(
	ctx context.Context,
) ([]model.Tenant, error) {

	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			id::text,
			name,
			created_at
		FROM tenants
		ORDER BY
			created_at ASC,
			id ASC
		`,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	tenants := make(
		[]model.Tenant,
		0,
	)

	for rows.Next() {
		var tenant model.Tenant

		if err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.CreatedAt,
		); err != nil {
			return nil, err
		}

		tenants = append(
			tenants,
			tenant,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tenants, nil
}

func (p *Postgres) CreateNode(ctx context.Context, tenantID, name, bootstrapHash string) (model.Node, error) {
	return p.CreateNodeForRuntime(ctx, tenantID, name, bootstrapHash, "xray")
}

func (p *Postgres) CreateNodeForRuntime(
	ctx context.Context,
	tenantID string,
	name string,
	bootstrapHash string,
	runtimeCore string,
) (model.Node, error) {

	if !model.ValidRuntimeCore(runtimeCore) {
		return model.Node{}, ErrNodeRuntime
	}
	var node model.Node

	err := p.Pool.QueryRow(
		ctx,
		`
		INSERT INTO nodes(
			tenant_id,
			name,
			bootstrap_token_hash,
 runtime_core
		)
		VALUES($1, $2, $3, $4)
		RETURNING
			id::text,
			tenant_id::text,
			name,
			status,
			desired_generation,
			applied_generation,
			last_seen_at,
			created_at,
			runtime_core
		`,
		tenantID,
		name,
		bootstrapHash,
		runtimeCore,
	).Scan(
		&node.ID,
		&node.TenantID,
		&node.Name,
		&node.Status,
		&node.DesiredGeneration,
		&node.AppliedGeneration,
		&node.LastSeenAt,
		&node.CreatedAt,
		&node.RuntimeCore,
	)

	return node, err
}

func (p *Postgres) ListNodes(
	ctx context.Context,
) ([]model.Node, error) {
	return p.ListNodesByDeletion(ctx, false)
}

func (p *Postgres) ListNodesByDeletion(ctx context.Context, deleted bool) ([]model.Node, error) {
	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			id::text,
			tenant_id::text,
			name,
			status,
			COALESCE(agent_version, ''),
			COALESCE(os_name, ''),
			COALESCE(os_version, ''),
			COALESCE(architecture, ''),
			desired_generation,
			applied_generation,
			last_seen_at,
			created_at,
			runtime_core
		FROM nodes
		WHERE (status='retired')=$1
		ORDER BY created_at ASC
		`, deleted,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	nodes := make([]model.Node, 0)

	for rows.Next() {
		var node model.Node

		if err := rows.Scan(
			&node.ID,
			&node.TenantID,
			&node.Name,
			&node.Status,
			&node.AgentVersion,
			&node.OSName,
			&node.OSVersion,
			&node.Architecture,
			&node.DesiredGeneration,
			&node.AppliedGeneration,
			&node.LastSeenAt,
			&node.CreatedAt,
			&node.RuntimeCore,
		); err != nil {
			return nil, err
		}

		nodes = append(nodes, node)
	}

	return nodes, rows.Err()
}

func (p *Postgres) DeploymentRecoveryFacts(
	ctx context.Context,
	nodeID string,
	generation int64,
	evaluatedAt time.Time,
) (model.RecoveryFacts, error) {
	var facts model.RecoveryFacts
	var lastSeenAt *time.Time
	var healthCheckedAt *time.Time
	var reportedHealthy bool

	err :=
		p.Pool.QueryRow(
			ctx,
			`
			SELECT
				d.id::text,
				d.node_id::text,
				d.generation,
				d.status,

				COALESCE(
					d.execution_id::text,
					''
				),
				COALESCE(
					d.execution_epoch,
					0
				),

				COALESCE(
					el.state,
					''
				),
				COALESCE(
					ef.state,
					''
				),

				COALESCE(
					(
						el.state = 'fenced'
						AND ef.state = 'acknowledged'

						AND el.owner_instance_id IS NOT NULL

						AND ef.target_owner_instance_id =
							el.owner_instance_id

						AND ef.acknowledged_by_instance_id =
							el.owner_instance_id

						AND el.fenced_at IS NOT NULL
						AND ef.acknowledged_at IS NOT NULL
					),
					false
				),

				COALESCE(
					d.requested_core_version,
					''
				),
				COALESCE(
					d.applied_core_version,
					''
				),

				d.updated_at,

				n.desired_generation,
				n.applied_generation,
				n.last_seen_at,

				COALESCE(
					nh.healthy,
					false
				),
				COALESCE(
					nh.applied_generation,
					0
				),
				COALESCE(
					nh.core_version,
					''
				),
				nh.checked_at

			FROM deployments d

			JOIN nodes n
				ON n.id = d.node_id

			LEFT JOIN deployment_execution_leases el
				ON el.deployment_id = d.id
				AND el.node_id = d.node_id
				AND el.generation = d.generation
				AND el.execution_id = d.execution_id
				AND el.execution_epoch = d.execution_epoch

			LEFT JOIN LATERAL (
				SELECT
					f.state,
					f.target_owner_instance_id,
					f.acknowledged_by_instance_id,
					f.acknowledged_at
				FROM execution_fence_requests f
				WHERE f.deployment_id = d.id
				  AND f.node_id = d.node_id
				  AND f.generation = d.generation
				  AND f.execution_id = d.execution_id
				  AND f.execution_epoch =
						d.execution_epoch
				  AND f.state = 'acknowledged'
				ORDER BY f.acknowledged_at DESC
				LIMIT 1
			) ef ON true

			LEFT JOIN LATERAL (
				SELECT
					healthy,
					applied_generation,
					core_version,
					checked_at
				FROM node_health
				WHERE node_id = d.node_id
				ORDER BY checked_at DESC
				LIMIT 1
			) nh ON true

			WHERE d.node_id = $1::uuid
			  AND d.generation = $2::bigint
			`,
			nodeID,
			generation,
		).Scan(
			&facts.DeploymentID,
			&facts.NodeID,
			&facts.Generation,
			&facts.Status,

			&facts.ExecutionID,
			&facts.ExecutionEpoch,

			&facts.LeaseState,
			&facts.FenceState,
			&facts.PhysicalFenceProven,

			&facts.RequestedCoreVersion,
			&facts.AppliedCoreVersion,

			&facts.DeploymentUpdatedAt,

			&facts.DesiredGeneration,
			&facts.AppliedGeneration,
			&lastSeenAt,

			&reportedHealthy,
			&facts.HealthAppliedGeneration,
			&facts.CurrentCoreVersion,
			&healthCheckedAt,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.RecoveryFacts{},
			ErrNotFound
	}

	if err != nil {
		return model.RecoveryFacts{},
			err
	}

	facts.NodeOnline =
		lastSeenAt != nil &&
			!lastSeenAt.Before(
				evaluatedAt.Add(
					-nodeOnlineWindow,
				),
			)

	facts.HealthFresh =
		healthCheckedAt != nil &&
			!healthCheckedAt.Before(
				evaluatedAt.Add(
					-nodeOnlineWindow,
				),
			)

	facts.NodeHealthy =
		facts.HealthFresh &&
			reportedHealthy

	age :=
		evaluatedAt.Sub(
			facts.DeploymentUpdatedAt,
		)

	if age < 0 {
		age = 0
	}

	facts.OperationalState,
		facts.Stuck,
		_ =
		deploymentOperationalState(
			facts.Status,
			age,
		)

	return facts, nil
}
func (p *Postgres) ListDeploymentObservations(
	ctx context.Context,
	nodeID string,
	observedAt time.Time,
) ([]model.DeploymentObservation, error) {
	var lastSeenAt *time.Time

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT last_seen_at
		FROM nodes
		WHERE id = $1::uuid
		`,
		nodeID,
	).Scan(
		&lastSeenAt,
	)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	nodeOnline :=
		lastSeenAt != nil &&
			observedAt.Sub(
				*lastSeenAt,
			) <= nodeOnlineWindow

	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			id::text,
			node_id::text,
			generation,
			status,
			COALESCE(
				previous_core_version,
				''
			),
			COALESCE(
				requested_core_version,
				''
			),
			COALESCE(
				applied_core_version,
				''
			),
			COALESCE(
				error_message,
				''
			),
			COALESCE(
				core_release_id::text,
				''
			),
			COALESCE(
				core_type,
				''
			),
			started_at,
			completed_at,
			updated_at

		FROM deployments

		WHERE node_id = $1::uuid

		ORDER BY generation DESC
		`,
		nodeID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	result :=
		make(
			[]model.DeploymentObservation,
			0,
		)

	for rows.Next() {
		var item model.DeploymentObservation

		err := rows.Scan(
			&item.ID,
			&item.NodeID,
			&item.Generation,
			&item.Status,
			&item.PreviousCoreVersion,
			&item.RequestedCoreVersion,
			&item.AppliedCoreVersion,
			&item.ErrorMessage,
			&item.CoreReleaseID,
			&item.CoreType,
			&item.StartedAt,
			&item.CompletedAt,
			&item.UpdatedAt,
		)

		if err != nil {
			return nil, err
		}

		age :=
			observedAt.Sub(
				item.UpdatedAt,
			)

		if age < 0 {
			age = 0
		}

		item.AgeSeconds =
			int64(
				age / time.Second,
			)

		item.NodeOnline =
			nodeOnline

		item.OperationalState,
			item.Stuck,
			item.StuckReason =
			deploymentOperationalState(
				item.Status,
				age,
			)

		result =
			append(
				result,
				item,
			)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (p *Postgres) SaveDesiredState(
	ctx context.Context,
	nodeID string,
	state model.DesiredState,
	coreReleaseID string,
) error {

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	if err := saveDesiredStateTx(
		ctx,
		tx,
		nodeID,
		state,
		coreReleaseID,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func saveDesiredStateTx(
	ctx context.Context,
	tx pgx.Tx,
	nodeID string,
	state model.DesiredState,
	coreReleaseID string,
) error {

	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}

	var currentGeneration int64
	var tenantID string
	var previousCoreVersion string

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			n.desired_generation,
			n.tenant_id::text,
			COALESCE(h.core_version, '')
		FROM nodes n
		LEFT JOIN node_health h
			ON h.node_id = n.id
		WHERE n.id = $1
		FOR UPDATE OF n
		`,
		nodeID,
	).Scan(
		&currentGeneration,
		&tenantID,
		&previousCoreVersion,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	if state.Generation <= currentGeneration {
		return errors.New(
			"generation must be greater than current desired generation",
		)
	}
	if err := validateXrayCascadeDesiredTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return err
	}
	if err := validateXrayProfileDesiredTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return err
	}
	if err := validateHysteriaDesiredTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return err
	}
	if err := validateVLESSTransportDesiredTx(ctx, tx, nodeID, state); err != nil {
		return err
	}
	if err := validateShadowsocksDesiredTx(ctx, tx, nodeID, state); err != nil {
		return err
	}
	if err := validateWireGuardDesiredTx(ctx, tx, nodeID, state); err != nil {
		return err
	}
	if err := validateNativeWireGuardDesiredTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return err
	}
	if err := validatePPTPDesiredTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return err
	}
	if err := validateOpenVPNDesiredTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO desired_states(
			node_id,
			generation,
			document
		)
		VALUES($1, $2, $3::jsonb)
		`,
		nodeID,
		state.Generation,
		string(raw),
	)

	if err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE nodes
		SET desired_generation = $2
		WHERE id = $1
		`,
		nodeID,
		state.Generation,
	)

	if err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO deployments(
			node_id,
			generation,
			status,
			previous_core_version,
			requested_core_version,
			core_release_id,
			core_type,
			updated_at
		)
		VALUES(
			$1,
			$2,
			'pending',
			NULLIF($3, ''),
			$4,
			$5,
			$6,
			now()
		)
		`,
		nodeID,
		state.Generation,
		previousCoreVersion,
		state.Core.Version,
		coreReleaseID,
		state.Core.Type,
	)

	if err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1,
			$2,
			'desired_state.accepted',
			'admin',
			'control-plane',
			jsonb_build_object(
				'generation', $3::bigint,
				'core_type', $4::text,
				'core_version', $5::text,
				'core_release_id', $6::uuid
			)
		)
		`,
		tenantID,
		nodeID,
		state.Generation,
		state.Core.Type,
		state.Core.Version,
		coreReleaseID,
	)

	return err
}

func (p *Postgres) BootstrapAgent(ctx context.Context, bootstrapHash, agentTokenHash, agentVersion, osName, osVersion, architecture string) (model.Node, error) {
	return p.BootstrapAgentForRuntime(ctx, bootstrapHash, agentTokenHash, agentVersion, osName, osVersion, architecture, "xray")
}

func (p *Postgres) BootstrapAgentForRuntime(
	ctx context.Context,
	bootstrapHash string,
	agentTokenHash string,
	agentVersion string,
	osName string,
	osVersion string,
	architecture string,
	runtimeCore string,
) (model.Node, error) {

	if !model.ValidRuntimeCore(runtimeCore) || (runtimeCore == "pptp" && !model.PPTPAgentCompatible(agentVersion)) || (runtimeCore == "wireguard" && !model.NativeWireGuardAgentCompatible(agentVersion)) || (runtimeCore == "openvpn" && !model.OpenVPNAgentCompatible(agentVersion)) || (runtimeCore == "hysteria2" && !HysteriaAgentOperationallyCompatible(agentVersion)) {
		return model.Node{}, ErrNodeRuntime
	}
	var node model.Node

	err := p.Pool.QueryRow(
		ctx,
		`
		UPDATE nodes
		SET
			bootstrap_used_at = now(),
			bootstrap_token_hash = NULL,
			agent_token_hash = $2,
			agent_version = $3,
			os_name = $4,
			os_version = $5,
			architecture = $6,
			status = 'online',
			last_seen_at = now()
		WHERE
			bootstrap_token_hash = $1
			AND bootstrap_used_at IS NULL
 AND runtime_core = $7
		RETURNING
			id::text,
			tenant_id::text,
			name,
			status,
			COALESCE(agent_version, ''),
			COALESCE(os_name, ''),
			COALESCE(os_version, ''),
			COALESCE(architecture, ''),
			desired_generation,
			applied_generation,
			last_seen_at,
			created_at,
			runtime_core
		`,
		bootstrapHash,
		agentTokenHash,
		agentVersion,
		osName,
		osVersion,
		architecture,
		runtimeCore,
	).Scan(
		&node.ID,
		&node.TenantID,
		&node.Name,
		&node.Status,
		&node.AgentVersion,
		&node.OSName,
		&node.OSVersion,
		&node.Architecture,
		&node.DesiredGeneration,
		&node.AppliedGeneration,
		&node.LastSeenAt,
		&node.CreatedAt,
		&node.RuntimeCore,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.Node{}, ErrNotFound
	}

	return node, err
}

func (p *Postgres) NodeByAgentToken(
	ctx context.Context,
	agentHash string,
) (model.Node, error) {

	var node model.Node

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			id::text,
			tenant_id::text,
			name,
			status,
			COALESCE(agent_version, ''),
			COALESCE(os_name, ''),
			COALESCE(os_version, ''),
			COALESCE(architecture, ''),
			desired_generation,
			applied_generation,
			last_seen_at,
			created_at,
			runtime_core
		FROM nodes
		WHERE agent_token_hash = $1
		`,
		agentHash,
	).Scan(
		&node.ID,
		&node.TenantID,
		&node.Name,
		&node.Status,
		&node.AgentVersion,
		&node.OSName,
		&node.OSVersion,
		&node.Architecture,
		&node.DesiredGeneration,
		&node.AppliedGeneration,
		&node.LastSeenAt,
		&node.CreatedAt,
		&node.RuntimeCore,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.Node{}, ErrNotFound
	}

	return node, err
}

func (p *Postgres) LatestDesiredState(
	ctx context.Context,
	nodeID string,
) (model.DesiredState, bool, error) {

	var raw []byte

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT document
		FROM desired_states
		WHERE node_id = $1
		ORDER BY generation DESC
		LIMIT 1
		`,
		nodeID,
	).Scan(&raw)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, false, nil
	}

	if err != nil {
		return model.DesiredState{}, false, err
	}

	var state model.DesiredState

	if err := json.Unmarshal(
		raw,
		&state,
	); err != nil {
		return model.DesiredState{}, false, err
	}

	return state, true, nil
}

func (p *Postgres) SaveHealth(
	ctx context.Context,
	nodeID string,
	report model.HealthReport,
) error {
	var selected string
	if err := p.Pool.QueryRow(ctx, `SELECT runtime_core FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&selected); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if (selected == "pptp" && (report.Core != selected || !model.PPTPAgentCompatible(report.AgentVersion))) || (selected == "wireguard" && (report.Core != selected || !model.NativeWireGuardAgentCompatible(report.AgentVersion))) || (selected == "openvpn" && (report.Core != selected || !model.OpenVPNAgentCompatible(report.AgentVersion))) || (selected == "hysteria2" && (report.Core != selected || !HysteriaAgentOperationallyCompatible(report.AgentVersion))) || (selected == "xray" && report.Core != "" && report.Core != selected) {
		return ErrNodeRuntime
	}
	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	// node_health is observational telemetry. It may contain
	// a stale local Agent checkpoint after a crash and therefore
	// must not be treated as the authoritative node generation.
	_, err =
		tx.Exec(
			ctx,
			`
			INSERT INTO node_health(
				node_id,
				healthy,
				applied_generation,
				core,
				core_version,
				message,
				checked_at
			)
			VALUES(
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7
			)

			ON CONFLICT(node_id)
			DO UPDATE SET
				healthy =
					EXCLUDED.healthy,

				applied_generation =
					EXCLUDED.applied_generation,

				core =
					EXCLUDED.core,

				core_version =
					EXCLUDED.core_version,

				message =
					EXCLUDED.message,

				checked_at =
					EXCLUDED.checked_at
			`,
			nodeID,
			report.Healthy,
			report.AppliedGeneration,
			report.Core,
			report.CoreVersion,
			report.Message,
			report.CheckedAt,
		)

	if err != nil {
		return err
	}

	_, err =
		tx.Exec(
			ctx,
			`
			UPDATE node_health
			SET
				last_known_good_core_version =
					NULLIF($2, ''),
				snapshot_count = $3,
				latest_snapshot_id =
					NULLIF($4, ''),
				rollback_ready = $5
			WHERE node_id = $1
			`,
			nodeID,
			report.LastKnownGoodCoreVersion,
			report.SnapshotCount,
			report.LatestSnapshotID,
			report.RollbackReady,
		)
	if err != nil {
		return err
	}

	if err = saveNodeMetrics(ctx, tx, nodeID, report.Metrics); err != nil {
		return err
	}

	samples := report.ClientTraffic
	epoch := ""
	var sequence int64
	if report.TrafficSnapshot != nil {
		samples = report.TrafficSnapshot.Clients
		epoch = report.TrafficSnapshot.Epoch
		sequence = report.TrafficSnapshot.Sequence
	}
	if len(samples) > 0 {
		var tenantID string
		if err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&tenantID); err != nil {
			return err
		}
		if err = lockTenantAccess(ctx, tx, tenantID); err != nil {
			return err
		}
		// A node that switched to durable delivery must not let an older agent's
		// inline report bypass samples still queued on disk after rollback.
		var durableDelivery bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_traffic_delivery WHERE node_id=$1::uuid)`, nodeID).Scan(&durableDelivery); err != nil {
			return err
		}
		if durableDelivery {
			samples = nil
		}
		crossed, err := saveClientTraffic(ctx, tx, nodeID, samples, time.Now().UTC(), epoch, sequence)
		if err != nil {
			return err
		}
		for _, clientID := range crossed {
			var credential string
			if err = tx.QueryRow(ctx, `SELECT vless_uuid::text FROM vpn_clients WHERE id=$1::uuid`, clientID).Scan(&credential); err != nil {
				return err
			}
			rebuilds, err := rebuildClientAccessNodes(ctx, tx, clientID, credential)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.traffic_quota_exceeded','system','traffic-accounting',jsonb_build_object('client_id',$2::text,'rebuild_count',$3::integer))`, tenantID, clientID, rebuilds)
			if err != nil {
				return err
			}
		}
	}

	status :=
		"online"

	if !report.Healthy {
		status =
			"degraded"
	}

	// Heartbeats update liveness and Agent metadata only.
	// They are explicitly forbidden from changing the
	// authoritative nodes.applied_generation checkpoint.
	_, err =
		tx.Exec(
			ctx,
			`
			UPDATE nodes
			SET
				status = CASE WHEN status='decommissioning' THEN status ELSE $2 END,

				agent_version =
					COALESCE(
						NULLIF(
							$3,
							''
						),
						agent_version
					),

				os_name =
					COALESCE(
						NULLIF(
							$4,
							''
						),
						os_name
					),

				os_version =
					COALESCE(
						NULLIF(
							$5,
							''
						),
						os_version
					),

				architecture =
					COALESCE(
						NULLIF(
							$6,
							''
						),
						architecture
					),

				last_seen_at =
					NOW()

			WHERE id = $1
			`,
			nodeID,
			status,
			report.AgentVersion,
			report.OSName,
			report.OSVersion,
			report.Architecture,
		)

	if err != nil {
		return err
	}

	// Temporary compatibility path for pre-lease Agents.
	//
	// Health may reconcile an unconfirmed healthy deployment
	// only when:
	//   1. it is the node's current desired generation;
	//   2. the deployment is still non-terminal;
	//   3. no execution lease exists for that deployment.
	//
	// Once a lease row exists, health is never allowed to
	// mutate deployment lifecycle state.
	if report.Healthy &&
		report.AppliedGeneration > 0 {

		tag, err :=
			tx.Exec(
				ctx,
				`
				UPDATE deployments d
				SET
					status = 'healthy',

					applied_core_version =
						NULLIF(
							$3::text,
							''
						),

					error_message =
						NULL,

					completed_at =
						COALESCE(
							completed_at,
							$4::timestamptz
						),

					updated_at =
						now()

				FROM nodes n

				WHERE d.node_id = $1::uuid
				  AND d.generation = $2::bigint
				  AND d.status IN (
						'pending',
						'applying'
				  )

				  AND n.id = d.node_id
				  AND n.desired_generation = $2::bigint

				  AND NOT EXISTS (
						SELECT 1
						FROM deployment_execution_leases l
						WHERE l.deployment_id = d.id
				  )
				`,
				nodeID,
				report.AppliedGeneration,
				report.CoreVersion,
				report.CheckedAt,
			)

		if err != nil {
			return err
		}

		if tag.RowsAffected() > 0 {
			// The legacy reconciliation above produced an
			// authoritative deployment transition. Advance the
			// node checkpoint from that transition, not directly
			// from the heartbeat itself.
			_, err =
				tx.Exec(
					ctx,
					`
					UPDATE nodes
					SET
						applied_generation =
							$2::bigint

					WHERE id =
						$1::uuid

					  AND desired_generation =
						$2::bigint

					  AND applied_generation <
						$2::bigint
					`,
					nodeID,
					report.AppliedGeneration,
				)

			if err != nil {
				return err
			}

			_, err =
				tx.Exec(
					ctx,
					`
					INSERT INTO audit_events(
						tenant_id,
						node_id,
						event_type,
						actor_type,
						actor_id,
						payload,
						created_at
					)

					SELECT
						tenant_id,
						$1::uuid,
						'deployment.healthy.reconciled',
						'control-plane',
						'health-reconciler',

						jsonb_build_object(
							'generation',
								$2::bigint,

							'applied_core_version',
								$3::text,

							'legacy_no_lease',
								true
						),

						$4::timestamptz

					FROM nodes

					WHERE id =
						$1::uuid
					`,
					nodeID,
					report.AppliedGeneration,
					report.CoreVersion,
					report.CheckedAt,
				)

			if err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

type ResolvedCoreRelease struct {
	ID      string
	Release model.CoreRelease
}

func (p *Postgres) ResolveCoreRelease(
	ctx context.Context,
	nodeID string,
	coreType string,
	version string,
) (ResolvedCoreRelease, error) {

	var result ResolvedCoreRelease

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			cr.id::text,
			cr.core_type,
			cr.version,
			cr.download_url,
			cr.sha256,
			cr.channel
		FROM nodes n
		JOIN core_releases cr
			ON cr.core_type = $2
			AND cr.version = $3
			AND cr.architecture = COALESCE(n.architecture, '')
			AND cr.os =
				CASE
					WHEN lower(COALESCE(n.os_name, '')) IN (
						'ubuntu',
						'debian',
						'alpine',
						'centos',
						'rhel',
						'fedora',
						'rocky',
						'almalinux',
						'linux'
					)
					THEN 'linux'
					ELSE lower(COALESCE(n.os_name, ''))
				END
		WHERE n.id = $1
			AND n.runtime_core = cr.core_type
 AND cr.approved = true
			AND cr.revoked = false
		ORDER BY
			CASE cr.channel
				WHEN 'stable' THEN 1
				WHEN 'canary' THEN 2
				WHEN 'testing' THEN 3
				ELSE 4
			END
		LIMIT 1
		`,
		nodeID,
		coreType,
		version,
	).Scan(
		&result.ID,
		&result.Release.Type,
		&result.Release.Version,
		&result.Release.DownloadURL,
		&result.Release.SHA256,
		&result.Release.Channel,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return ResolvedCoreRelease{}, ErrNotFound
	}

	if err != nil {
		return ResolvedCoreRelease{}, err
	}

	return result, nil
}

func (p *Postgres) SaveDeploymentReport(
	ctx context.Context,
	nodeID string,
	report model.DeploymentReport,
) error {
	switch report.Status {
	case "applying",
		"healthy",
		"failed",
		"rolled_back":
	default:
		return errors.New(
			"invalid deployment status",
		)
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	if err :=
		lockExecutionNodeTx(
			ctx,
			tx,
			nodeID,
		); err != nil {

		return err
	}

	var tenantID string
	var deploymentID string
	var currentStatus string
	var executionID string
	var executionEpoch int64

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			n.tenant_id::text,
			d.id::text,
			d.status,
				d.execution_id::text,
				d.execution_epoch

		FROM deployments d

		JOIN nodes n
			ON n.id = d.node_id

		WHERE d.node_id = $1::uuid
		  AND d.generation = $2::bigint

		FOR UPDATE OF d
		`,
		nodeID,
		report.Generation,
	).Scan(
		&tenantID,
		&deploymentID,
		&currentStatus,
		&executionID,
		&executionEpoch,
	)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	if err :=
		validateDeploymentExecutionIdentity(
			report,
			deploymentID,
			executionID,
			executionEpoch,
		); err != nil {

		return err
	}

	changed, allowed :=
		deploymentTransition(
			currentStatus,
			report.Status,
		)

	if !allowed {
		return fmt.Errorf(
			"%w: %s -> %s",
			ErrInvalidDeploymentTransition,
			currentStatus,
			report.Status,
		)
	}

	// Once physical fencing has been requested for a live
	// execution, the old worker may no longer publish any
	// deployment state.
	//
	// This check intentionally applies to both changed and
	// repeated no-op reports while the deployment is live.
	//
	// Already-terminal idempotent retries retain the existing
	// D4B crash-consistency semantics.
	if currentStatus == "pending" ||
		currentStatus == "applying" {

		fenceRequested, err :=
			executionFenceRequestedTx(
				ctx,
				tx,
				deploymentID,
			)

		if err != nil {
			return err
		}

		if fenceRequested {
			return fmt.Errorf(
				"%w: execution fence requested",
				ErrExecutionLeaseConflict,
			)
		}
	}

	leaseState, leaseExists, err :=
		validateDeploymentLeaseProofTx(
			ctx,
			tx,
			nodeID,
			deploymentID,
			report,
		)

	if err != nil {
		return err
	}

	// A completed lease is accepted only for an
	// idempotent retry of an already-terminal deployment.
	// It must never authorize new execution work.
	if leaseExists &&
		!completedLeaseReportAllowed(
			leaseState,
			report.Status,
			changed,
		) {

		return ErrExecutionLeaseConflict
	}

	// Repeated reports for the exact same deployment
	// state are successful no-ops. Terminal retries
	// with an already-completed matching lease are
	// also idempotent.
	if !changed {
		if leaseExists &&
			report.Status != "applying" {

			switch leaseState {
			case "completed":

			case "active":
				if err :=
					completeDeploymentExecutionLeaseTx(
						ctx,
						tx,
						tenantID,
						nodeID,
						deploymentID,
						report,
					); err != nil {

					return err
				}

			default:
				return ErrExecutionLeaseConflict
			}
		}

		return tx.Commit(ctx)
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE deployments
		SET
			status = $2::text,

			applied_core_version =
				CASE
					WHEN $2::text IN (
						'healthy',
						'rolled_back'
					)
					THEN NULLIF(
						$3::text,
						''
					)
					ELSE NULL
				END,

			error_message =
				CASE
					WHEN $2::text IN (
						'failed',
						'rolled_back'
					)
					THEN NULLIF(
						$4::text,
						''
					)
					ELSE NULL
				END,

			completed_at =
				CASE
					WHEN $2::text = 'applying'
					THEN NULL
					ELSE $5::timestamptz
				END,

			updated_at = now()

		WHERE id = $1::uuid
		`,
		deploymentID,
		report.Status,
		report.AppliedCoreVersion,
		report.ErrorMessage,
		report.ReportedAt,
	)

	if err != nil {
		return err
	}

	// A successful terminal deployment is the authoritative
	// source of nodes.applied_generation. Health reports are
	// observations and must never advance or roll this value back.
	if report.Status == "healthy" {
		_, err =
			tx.Exec(
				ctx,
				`
				UPDATE nodes
				SET
					applied_generation = $2::bigint
				WHERE id = $1::uuid
				  AND desired_generation = $2::bigint
				  AND applied_generation < $2::bigint
				`,
				nodeID,
				report.Generation,
			)

		if err != nil {
			return err
		}
	}

	var rolloutPlanID string

	rolloutOutcomeChanged :=
		false

	err = tx.QueryRow(
		ctx,
		`
		UPDATE rollout_plans rp
		SET
			outcome_status = $2::text,

			outcome_at =
				CASE
					WHEN $2::text IN (
						'healthy',
						'failed',
						'rolled_back'
					)
					THEN $4::timestamptz
					ELSE NULL
				END,

			outcome_reason =
				CASE
					WHEN $2::text IN (
						'failed',
						'rolled_back'
					)
					THEN NULLIF(
						$3::text,
						''
					)
					ELSE NULL
				END,

			updated_at = now()

		WHERE rp.deployment_id = $1::uuid
		  AND rp.status = 'executed'

		RETURNING rp.id::text
		`,
		deploymentID,
		report.Status,
		report.ErrorMessage,
		report.ReportedAt,
	).Scan(
		&rolloutPlanID,
	)

	switch {
	case err == nil:
		rolloutOutcomeChanged =
			true

	case errors.Is(
		err,
		pgx.ErrNoRows,
	):
		err = nil

	default:
		return err
	}

	eventType :=
		"deployment." + report.Status

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload,
			created_at
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			$3::text,
			'agent',
			$2::text,
			jsonb_build_object(
				'deployment_id',
					$4::text,
				'generation',
					$5::bigint,
				'previous_status',
					$6::text,
				'status',
					$7::text,
				'applied_core_version',
					NULLIF(
						$8::text,
						''
					),
				'error_message',
					NULLIF(
						$9::text,
						''
					)
			),
			$10::timestamptz
		)
		`,
		tenantID,
		nodeID,
		eventType,
		deploymentID,
		report.Generation,
		currentStatus,
		report.Status,
		report.AppliedCoreVersion,
		report.ErrorMessage,
		report.ReportedAt,
	)

	if err != nil {
		return err
	}

	if rolloutOutcomeChanged {
		_, err = tx.Exec(
			ctx,
			`
			INSERT INTO audit_events(
				tenant_id,
				node_id,
				event_type,
				actor_type,
				actor_id,
				payload,
				created_at
			)
			VALUES(
				$1::uuid,
				$2::uuid,
				'rollout_plan.outcome_changed',
				'agent',
				$2::text,
				jsonb_build_object(
					'rollout_plan_id',
						$3::text,
					'deployment_id',
						$4::text,
					'generation',
						$5::bigint,
					'previous_status',
						$6::text,
					'outcome_status',
						$7::text,
					'applied_core_version',
						NULLIF(
							$8::text,
							''
						),
					'error_message',
						NULLIF(
							$9::text,
							''
						)
				),
				$10::timestamptz
			)
			`,
			tenantID,
			nodeID,
			rolloutPlanID,
			deploymentID,
			report.Generation,
			currentStatus,
			report.Status,
			report.AppliedCoreVersion,
			report.ErrorMessage,
			report.ReportedAt,
		)

		if err != nil {
			return err
		}
	}

	if leaseExists &&
		report.Status != "applying" {

		if leaseState != "active" {
			return ErrExecutionLeaseConflict
		}

		if err :=
			completeDeploymentExecutionLeaseTx(
				ctx,
				tx,
				tenantID,
				nodeID,
				deploymentID,
				report,
			); err != nil {

			return err
		}
	}

	return tx.Commit(ctx)
}

func (p *Postgres) ListCoreReleases(
	ctx context.Context,
) ([]model.CoreReleaseRecord, error) {

	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			id::text,
			core_type,
			version,
			os,
			architecture,
			download_url,
			lower(sha256),
			channel,
			upstream_prerelease,
			approved,
			revoked,
			COALESCE(approved_by, ''),
			COALESCE(approved_at::text, ''),
			created_at,
			updated_at
		FROM core_releases
		ORDER BY
			core_type,
			version,
			os,
			architecture
		`,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var releases []model.CoreReleaseRecord

	for rows.Next() {
		var release model.CoreReleaseRecord

		if err := rows.Scan(
			&release.ID,
			&release.Type,
			&release.Version,
			&release.OS,
			&release.Architecture,
			&release.DownloadURL,
			&release.SHA256,
			&release.Channel,
			&release.UpstreamPrerelease,
			&release.Approved,
			&release.Revoked,
			&release.ApprovedBy,
			&release.ApprovedAt,
			&release.CreatedAt,
			&release.UpdatedAt,
		); err != nil {
			return nil, err
		}

		releases = append(
			releases,
			release,
		)
	}

	return releases, rows.Err()
}

func (p *Postgres) CreateCoreRelease(
	ctx context.Context,
	release model.CoreReleaseRecord,
) (model.CoreReleaseRecord, error) {

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.CoreReleaseRecord{}, err
	}

	defer tx.Rollback(ctx)

	var created model.CoreReleaseRecord

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO core_releases(
			core_type,
			version,
			os,
			architecture,
			download_url,
			sha256,
			channel,
			upstream_prerelease
		)
		VALUES(
			$1,$2,$3,$4,$5,$6,$7,$8
		)
		RETURNING
			id::text,
			core_type,
			version,
			os,
			architecture,
			download_url,
			lower(sha256),
			channel,
			upstream_prerelease,
			approved,
			revoked,
			COALESCE(approved_by, ''),
			COALESCE(approved_at::text, ''),
			created_at,
			updated_at
		`,
		release.Type,
		release.Version,
		release.OS,
		release.Architecture,
		release.DownloadURL,
		release.SHA256,
		release.Channel,
		release.UpstreamPrerelease,
	).Scan(
		&created.ID,
		&created.Type,
		&created.Version,
		&created.OS,
		&created.Architecture,
		&created.DownloadURL,
		&created.SHA256,
		&created.Channel,
		&created.UpstreamPrerelease,
		&created.Approved,
		&created.Revoked,
		&created.ApprovedBy,
		&created.ApprovedAt,
		&created.CreatedAt,
		&created.UpdatedAt,
	)

	if err != nil {
		return model.CoreReleaseRecord{}, err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			'core_release.created',
			'admin',
			'control-plane',
			jsonb_build_object(
				'core_release_id', $1::text,
				'core_type', $2::text,
				'version', $3::text,
				'os', $4::text,
				'architecture', $5::text,
				'channel', $6::text
			)
		)
		`,
		created.ID,
		created.Type,
		created.Version,
		created.OS,
		created.Architecture,
		created.Channel,
	)

	if err != nil {
		return model.CoreReleaseRecord{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.CoreReleaseRecord{}, err
	}

	return created, nil
}

func (p *Postgres) ApproveCoreRelease(
	ctx context.Context,
	id string,
) error {

	tag, err := p.Pool.Exec(
		ctx,
		`
		UPDATE core_releases
		SET
			approved = true,
			approved_at = now(),
			approved_by = 'control-plane',
			updated_at = now()
		WHERE id = $1::uuid
		  AND revoked = false
		`,
		id,
	)

	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	_, err = p.Pool.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			'core_release.approved',
			'admin',
			'control-plane',
			jsonb_build_object(
				'core_release_id', $1::text
			)
		)
		`,
		id,
	)

	return err
}

func coreChannelRank(
	channel string,
) int {
	switch channel {
	case "testing":
		return 1
	case "canary":
		return 2
	case "stable":
		return 3
	default:
		return 0
	}
}

func (p *Postgres) PromoteCoreRelease(
	ctx context.Context,
	id string,
	channel string,
) error {

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	var currentChannel string
	var approved bool
	var revoked bool
	var upstreamPrerelease bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			channel,
			approved,
			revoked,
			upstream_prerelease
		FROM core_releases
		WHERE id = $1::uuid
		FOR UPDATE
		`,
		id,
	).Scan(
		&currentChannel,
		&approved,
		&revoked,
		&upstreamPrerelease,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	if revoked {
		return ErrCoreReleaseRevoked
	}

	if !approved {
		return ErrCoreReleaseNotApproved
	}

	if currentChannel == channel {
		return ErrCoreReleaseAlreadyChannel
	}

	currentRank :=
		coreChannelRank(currentChannel)

	targetRank :=
		coreChannelRank(channel)

	if currentRank == 0 ||
		targetRank == 0 {
		return errors.New(
			"invalid core release channel",
		)
	}

	if targetRank < currentRank {
		return ErrCoreReleaseDowngrade
	}

	if channel == "stable" &&
		upstreamPrerelease {
		return ErrCoreReleasePrereleaseStable
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE core_releases
		SET
			channel = $2::text,
			updated_at = now()
		WHERE id = $1::uuid
		`,
		id,
		channel,
	)

	if err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			'core_release.promoted',
			'admin',
			'control-plane',
			jsonb_build_object(
				'core_release_id', $1::text,
				'from_channel', $2::text,
				'to_channel', $3::text
			)
		)
		`,
		id,
		currentChannel,
		channel,
	)

	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (p *Postgres) RevokeCoreRelease(
	ctx context.Context,
	id string,
) error {

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	var revoked bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT revoked
		FROM core_releases
		WHERE id = $1::uuid
		FOR UPDATE
		`,
		id,
	).Scan(&revoked)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	if revoked {
		return ErrCoreReleaseAlreadyRevoked
	}

	_, err = tx.Exec(
		ctx,
		`
		UPDATE core_releases
		SET
			revoked = true,
			approved = false,
			updated_at = now()
		WHERE id = $1::uuid
		`,
		id,
	)

	if err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			'core_release.revoked',
			'admin',
			'control-plane',
			jsonb_build_object(
				'core_release_id', $1::text
			)
		)
		`,
		id,
	)

	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

var (
	ErrCoreReleaseNotApproved = errors.New("core release is not approved")

	ErrCoreReleaseRevoked = errors.New("core release is revoked")

	ErrCoreReleaseAlreadyApproved = errors.New("core release is already approved")

	ErrCoreReleaseAlreadyRevoked = errors.New("core release is already revoked")

	ErrCoreReleaseAlreadyChannel = errors.New("core release is already in requested channel")

	ErrCoreReleaseDowngrade = errors.New("core release channel downgrade is not allowed")

	ErrCoreReleasePrereleaseStable = errors.New("upstream prerelease cannot be promoted to stable")
)

var ErrCoreReleaseIntegrityConflict = errors.New("core release already exists with different artifact metadata")

func (p *Postgres) ImportCoreRelease(
	ctx context.Context,
	release model.CoreReleaseRecord,
	metadataJSON string,
) (model.CoreReleaseRecord, bool, error) {

	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.CoreReleaseRecord{}, false, err
	}

	defer tx.Rollback(ctx)

	var existing model.CoreReleaseRecord

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			id::text,
			core_type,
			version,
			os,
			architecture,
			download_url,
			lower(sha256),
			channel,
			upstream_prerelease,
			approved,
			revoked,
			COALESCE(approved_by, ''),
			COALESCE(approved_at::text, ''),
			created_at,
			updated_at
		FROM core_releases
		WHERE core_type = $1
		  AND version = $2
		  AND os = $3
		  AND architecture = $4
		FOR UPDATE
		`,
		release.Type,
		release.Version,
		release.OS,
		release.Architecture,
	).Scan(
		&existing.ID,
		&existing.Type,
		&existing.Version,
		&existing.OS,
		&existing.Architecture,
		&existing.DownloadURL,
		&existing.SHA256,
		&existing.Channel,
		&existing.UpstreamPrerelease,
		&existing.Approved,
		&existing.Revoked,
		&existing.ApprovedBy,
		&existing.ApprovedAt,
		&existing.CreatedAt,
		&existing.UpdatedAt,
	)

	if err == nil {
		if existing.DownloadURL != release.DownloadURL ||
			existing.SHA256 != release.SHA256 {

			return model.CoreReleaseRecord{},
				false,
				ErrCoreReleaseIntegrityConflict
		}

		err = tx.QueryRow(
			ctx,
			`
			UPDATE core_releases
			SET
				upstream_prerelease = $2,
				metadata =
					metadata || $3::jsonb,
				updated_at =
					CASE
						WHEN upstream_prerelease
							IS DISTINCT FROM $2
						THEN now()
						ELSE updated_at
					END
			WHERE id = $1::uuid
			RETURNING
				upstream_prerelease,
				updated_at
			`,
			existing.ID,
			release.UpstreamPrerelease,
			metadataJSON,
		).Scan(
			&existing.UpstreamPrerelease,
			&existing.UpdatedAt,
		)

		if err != nil {
			return model.CoreReleaseRecord{},
				false,
				err
		}

		if err := tx.Commit(ctx); err != nil {
			return model.CoreReleaseRecord{},
				false,
				err
		}

		return existing, false, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return model.CoreReleaseRecord{},
			false,
			err
	}

	var created model.CoreReleaseRecord

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO core_releases(
			core_type,
			version,
			os,
			architecture,
			download_url,
			sha256,
			channel,
			upstream_prerelease,
			approved,
			revoked,
			metadata
		)
		VALUES(
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			'testing',
			$7,
			false,
			false,
			$8::jsonb
		)
		RETURNING
			id::text,
			core_type,
			version,
			os,
			architecture,
			download_url,
			lower(sha256),
			channel,
			upstream_prerelease,
			approved,
			revoked,
			COALESCE(approved_by, ''),
			COALESCE(approved_at::text, ''),
			created_at,
			updated_at
		`,
		release.Type,
		release.Version,
		release.OS,
		release.Architecture,
		release.DownloadURL,
		release.SHA256,
		release.UpstreamPrerelease,
		metadataJSON,
	).Scan(
		&created.ID,
		&created.Type,
		&created.Version,
		&created.OS,
		&created.Architecture,
		&created.DownloadURL,
		&created.SHA256,
		&created.Channel,
		&created.UpstreamPrerelease,
		&created.Approved,
		&created.Revoked,
		&created.ApprovedBy,
		&created.ApprovedAt,
		&created.CreatedAt,
		&created.UpdatedAt,
	)

	if err != nil {
		return model.CoreReleaseRecord{},
			false,
			err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			'core_release.imported',
			'system',
			'xray-upstream-importer',
			jsonb_build_object(
				'core_release_id', $1::text,
				'core_type', $2::text,
				'version', $3::text,
				'os', $4::text,
				'architecture', $5::text,
				'channel', 'testing',
				'approved', false,
				'upstream_prerelease', $6::boolean
			)
		)
		`,
		created.ID,
		created.Type,
		created.Version,
		created.OS,
		created.Architecture,
		created.UpstreamPrerelease,
	)

	if err != nil {
		return model.CoreReleaseRecord{},
			false,
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.CoreReleaseRecord{},
			false,
			err
	}

	return created, true, nil
}

func (p *Postgres) GetCoreUpdateStatus(
	ctx context.Context,
	nodeID string,
	coreType string,
) (model.CoreUpdateStatus, error) {

	compatible, compatibilityErr := p.coreRuntimeCompatible(ctx, nodeID, coreType)
	if compatibilityErr != nil {
		return model.CoreUpdateStatus{}, compatibilityErr
	}
	var status model.CoreUpdateStatus

	var platformOS string
	var architecture string

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			n.id::text,

			CASE
				WHEN lower(COALESCE(n.os_name, '')) IN (
					'ubuntu',
					'debian',
					'alpine',
					'centos',
					'rhel',
					'fedora',
					'rocky',
					'almalinux',
					'linux'
				)
				THEN 'linux'
				ELSE lower(COALESCE(n.os_name, ''))
			END,

			COALESCE(n.architecture, ''),

			COALESCE(nh.core_version, ''),
			COALESCE(nh.applied_generation, 0),
			COALESCE(nh.healthy, false),

			COALESCE(p.policy, 'pinned'),

			COALESCE(
				p.pinned_version,
				NULLIF(nh.core_version, ''),
				''
			)

		FROM nodes n

		LEFT JOIN node_health nh
			ON nh.node_id = n.id
			AND nh.core = $2

		LEFT JOIN node_core_update_policies p
			ON p.node_id = n.id
			AND p.core_type = $2

		WHERE n.id = $1
		`,
		nodeID,
		coreType,
	).Scan(
		&status.NodeID,
		&platformOS,
		&architecture,
		&status.CurrentVersion,
		&status.CurrentGeneration,
		&status.CurrentHealthy,
		&status.Policy,
		&status.PinnedVersion,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.CoreUpdateStatus{},
			ErrNotFound
	}

	if err != nil {
		return model.CoreUpdateStatus{},
			err
	}

	status.CoreType = coreType

	switch status.Policy {
	case "pinned",
		"testing",
		"canary",
		"stable":

	default:
		return model.CoreUpdateStatus{},
			errors.New(
				"invalid node core update policy",
			)
	}

	if !compatible {
		return status, nil
	}
	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			id::text,
			version,
			channel, sha256, download_url
		FROM core_releases
		WHERE core_type = $1
		  AND os = $2
		  AND architecture = $3
		  AND approved = true
		  AND revoked = false
		`,
		coreType,
		platformOS,
		architecture,
	)

	if err != nil {
		return model.CoreUpdateStatus{},
			err
	}

	defer rows.Close()

	var candidateID string
	var candidateVersion string
	var candidateChannel string

	for rows.Next() {
		var releaseID string
		var version string
		var channel string
		var sha, downloadURL string

		if err := rows.Scan(
			&releaseID,
			&version,
			&channel, &sha, &downloadURL,
		); err != nil {

			return model.CoreUpdateStatus{},
				err
		}

		if !reviewedRuntimeArtifact(coreType, version, sha, downloadURL) {
			continue
		}
		if !coreReleaseAllowedByPolicy(
			status.Policy,
			status.PinnedVersion,
			version,
			channel,
		) {
			continue
		}

		if candidateVersion == "" ||
			compareCoreVersions(
				version,
				candidateVersion,
			) > 0 {

			candidateID =
				releaseID

			candidateVersion =
				version

			candidateChannel =
				channel
		}
	}

	if err := rows.Err(); err != nil {
		return model.CoreUpdateStatus{},
			err
	}

	if candidateVersion == "" {
		return status, nil
	}

	status.CandidateAvailable = true

	status.CandidateReleaseID =
		candidateID

	status.CandidateVersion =
		candidateVersion

	status.CandidateChannel =
		candidateChannel

	status.PolicySatisfied =
		status.CurrentVersion ==
			status.CandidateVersion

	if status.CurrentVersion == "" {
		status.UpdateAvailable = true
	} else {
		status.UpdateAvailable =
			compareCoreVersions(
				status.CandidateVersion,
				status.CurrentVersion,
			) > 0
	}

	return status, nil
}

func coreReleaseAllowedByPolicy(
	policy string,
	pinnedVersion string,
	releaseVersion string,
	releaseChannel string,
) bool {

	switch policy {
	case "pinned":
		return releaseVersion ==
			pinnedVersion

	case "testing":
		return releaseChannel == "testing" ||
			releaseChannel == "canary" ||
			releaseChannel == "stable"

	case "canary":
		return releaseChannel == "canary" ||
			releaseChannel == "stable"

	case "stable":
		return releaseChannel == "stable"

	default:
		return false
	}
}

func compareCoreVersions(
	left string,
	right string,
) int {

	left =
		strings.TrimPrefix(
			strings.TrimPrefix(
				strings.TrimSpace(left),
				"v",
			),
			"V",
		)

	right =
		strings.TrimPrefix(
			strings.TrimPrefix(
				strings.TrimSpace(right),
				"v",
			),
			"V",
		)

	leftParts, leftNumeric :=
		numericVersionParts(left)

	rightParts, rightNumeric :=
		numericVersionParts(right)

	if leftNumeric && rightNumeric {
		maxParts :=
			len(leftParts)

		if len(rightParts) > maxParts {
			maxParts =
				len(rightParts)
		}

		for i := 0; i < maxParts; i++ {
			var l int64
			var r int64

			if i < len(leftParts) {
				l = leftParts[i]
			}

			if i < len(rightParts) {
				r = rightParts[i]
			}

			switch {
			case l > r:
				return 1

			case l < r:
				return -1
			}
		}

		return 0
	}

	return strings.Compare(
		left,
		right,
	)
}

func numericVersionParts(
	version string,
) ([]int64, bool) {

	rawParts :=
		strings.Split(
			version,
			".",
		)

	if len(rawParts) == 0 {
		return nil, false
	}

	parts :=
		make(
			[]int64,
			0,
			len(rawParts),
		)

	for _, raw := range rawParts {

		if raw == "" {
			return nil, false
		}

		value, err :=
			strconv.ParseInt(
				raw,
				10,
				64,
			)

		if err != nil {
			return nil, false
		}

		parts =
			append(
				parts,
				value,
			)
	}

	return parts, true
}

var (
	ErrInvalidCoreUpdatePolicy = errors.New("invalid core update policy")

	ErrPinnedVersionRequired = errors.New("pinned version is required for pinned policy")

	ErrPinnedVersionNotAllowed = errors.New("pinned version is only allowed for pinned policy")

	ErrPinnedCoreReleaseUnavailable = errors.New("pinned core release is not approved or not available for node platform")
)

func (p *Postgres) SetCoreUpdatePolicy(
	ctx context.Context,
	nodeID string,
	coreType string,
	policy string,
	pinnedVersion string,
) (model.CoreUpdatePolicy, bool, error) {

	nodeID =
		strings.TrimSpace(nodeID)

	coreType =
		strings.TrimSpace(coreType)

	policy =
		strings.TrimSpace(policy)

	pinnedVersion =
		strings.TrimSpace(pinnedVersion)

	compatible, err := p.coreRuntimeCompatible(ctx, nodeID, coreType)
	if err != nil {
		return model.CoreUpdatePolicy{}, false, err
	}
	if !compatible {
		return model.CoreUpdatePolicy{}, false, ErrNodeRuntime
	}
	switch policy {
	case "pinned":
		if pinnedVersion == "" {
			return model.CoreUpdatePolicy{},
				false,
				ErrPinnedVersionRequired
		}

	case "testing", "canary", "stable":
		if pinnedVersion != "" {
			return model.CoreUpdatePolicy{},
				false,
				ErrPinnedVersionNotAllowed
		}

	default:
		return model.CoreUpdatePolicy{},
			false,
			ErrInvalidCoreUpdatePolicy
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.CoreUpdatePolicy{},
			false,
			err
	}

	defer tx.Rollback(ctx)

	var tenantID string

	err = tx.QueryRow(
		ctx,
		`
		SELECT tenant_id::text
		FROM nodes
		WHERE id = $1
		`,
		nodeID,
	).Scan(
		&tenantID,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.CoreUpdatePolicy{},
			false,
			ErrNotFound
	}

	if err != nil {
		return model.CoreUpdatePolicy{},
			false,
			err
	}

	if policy == "pinned" {
		var releaseAvailable bool

		err = tx.QueryRow(
			ctx,
			`
			SELECT EXISTS(
				SELECT 1
				FROM nodes n
				JOIN core_releases cr
					ON cr.core_type = $2
					AND cr.version = $3
					AND cr.architecture =
						COALESCE(n.architecture, '')
					AND cr.os =
						CASE
							WHEN lower(
								COALESCE(
									n.os_name,
									''
								)
							) IN (
								'ubuntu',
								'debian',
								'alpine',
								'centos',
								'rhel',
								'fedora',
								'rocky',
								'almalinux',
								'linux'
							)
							THEN 'linux'
							ELSE lower(
								COALESCE(
									n.os_name,
									''
								)
							)
						END
				WHERE n.id = $1
				  AND cr.approved = true
				  AND cr.revoked = false
				  AND (cr.core_type <> 'hysteria2' OR (cr.version=$4 AND cr.sha256=$5 AND cr.download_url=$6))
			)
			`,
			nodeID,
			coreType,
			pinnedVersion, model.HysteriaPinnedVersion, model.HysteriaPinnedSHA256, model.HysteriaPinnedDownloadURL,
		).Scan(
			&releaseAvailable,
		)

		if err != nil {
			return model.CoreUpdatePolicy{},
				false,
				err
		}

		if !releaseAvailable {
			return model.CoreUpdatePolicy{},
				false,
				ErrPinnedCoreReleaseUnavailable
		}
	}

	var existing model.CoreUpdatePolicy

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			node_id::text,
			core_type,
			policy,
			COALESCE(pinned_version, ''),
			created_at,
			updated_at
		FROM node_core_update_policies
		WHERE node_id = $1
		  AND core_type = $2
		FOR UPDATE
		`,
		nodeID,
		coreType,
	).Scan(
		&existing.NodeID,
		&existing.CoreType,
		&existing.Policy,
		&existing.PinnedVersion,
		&existing.CreatedAt,
		&existing.UpdatedAt,
	)

	existingFound :=
		err == nil

	if err != nil &&
		!errors.Is(err, pgx.ErrNoRows) {

		return model.CoreUpdatePolicy{},
			false,
			err
	}

	if existingFound &&
		existing.Policy == policy &&
		existing.PinnedVersion == pinnedVersion {

		if err := tx.Commit(ctx); err != nil {
			return model.CoreUpdatePolicy{},
				false,
				err
		}

		return existing,
			false,
			nil
	}

	previousPolicy := ""
	previousPinnedVersion := ""

	if existingFound {
		previousPolicy =
			existing.Policy

		previousPinnedVersion =
			existing.PinnedVersion
	}

	var saved model.CoreUpdatePolicy

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO node_core_update_policies(
			node_id,
			core_type,
			policy,
			pinned_version
		)
		VALUES(
			$1,
			$2,
			$3,
			NULLIF($4, '')
		)
		ON CONFLICT(node_id, core_type)
		DO UPDATE SET
			policy = EXCLUDED.policy,
			pinned_version = EXCLUDED.pinned_version,
			updated_at = now()
		RETURNING
			node_id::text,
			core_type,
			policy,
			COALESCE(pinned_version, ''),
			created_at,
			updated_at
		`,
		nodeID,
		coreType,
		policy,
		pinnedVersion,
	).Scan(
		&saved.NodeID,
		&saved.CoreType,
		&saved.Policy,
		&saved.PinnedVersion,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	)

	if err != nil {
		return model.CoreUpdatePolicy{},
			false,
			err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			'node_core_update_policy.changed',
			'admin',
			'control-plane',
			jsonb_build_object(
				'core_type', $3::text,
				'previous_policy',
					NULLIF($4::text, ''),
				'previous_pinned_version',
					NULLIF($5::text, ''),
				'policy', $6::text,
				'pinned_version',
					NULLIF($7::text, '')
			)
		)
		`,
		tenantID,
		nodeID,
		coreType,
		previousPolicy,
		previousPinnedVersion,
		policy,
		pinnedVersion,
	)

	if err != nil {
		return model.CoreUpdatePolicy{},
			false,
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.CoreUpdatePolicy{},
			false,
			err
	}

	return saved,
		true,
		nil
}

func (p *Postgres) EvaluateCoreUpdate(
	ctx context.Context,
	nodeID string,
	coreType string,
	version string,
) (model.CoreUpdateEvaluation, error) {

	nodeID =
		strings.TrimSpace(nodeID)

	coreType =
		strings.TrimSpace(coreType)

	version =
		strings.TrimSpace(version)

	compatible, compatibilityErr := p.coreRuntimeCompatible(ctx, nodeID, coreType)
	if compatibilityErr != nil {
		return model.CoreUpdateEvaluation{}, compatibilityErr
	}
	var result model.CoreUpdateEvaluation

	result.NodeID = nodeID
	result.CoreType = coreType
	result.Version = version
	result.Blockers = []string{}
	if !compatible {
		result.Blockers = append(result.Blockers, "incompatible_agent_or_platform")
	}

	var platformOS string
	var architecture string

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			CASE
				WHEN lower(COALESCE(n.os_name, '')) IN (
					'ubuntu',
					'debian',
					'alpine',
					'centos',
					'rhel',
					'fedora',
					'rocky',
					'almalinux',
					'linux'
				)
				THEN 'linux'
				ELSE lower(COALESCE(n.os_name, ''))
			END,

			COALESCE(n.architecture, ''),

			COALESCE(nh.core_version, ''),

			COALESCE(p.policy, 'pinned'),

			COALESCE(
				p.pinned_version,
				NULLIF(nh.core_version, ''),
				''
			)

		FROM nodes n

		LEFT JOIN node_health nh
			ON nh.node_id = n.id
			AND nh.core = $2

		LEFT JOIN node_core_update_policies p
			ON p.node_id = n.id
			AND p.core_type = $2

		WHERE n.id = $1
		`,
		nodeID,
		coreType,
	).Scan(
		&platformOS,
		&architecture,
		&result.CurrentVersion,
		&result.Policy,
		&result.PinnedVersion,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.CoreUpdateEvaluation{},
			ErrNotFound
	}

	if err != nil {
		return model.CoreUpdateEvaluation{},
			err
	}

	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			os,
			architecture,
			channel,
			approved,
			revoked, sha256, download_url
		FROM core_releases
		WHERE core_type = $1
		  AND version = $2
		ORDER BY
			CASE
				WHEN os = $3
				 AND architecture = $4
				THEN 0
				ELSE 1
			END,
			os,
			architecture
		`,
		coreType,
		version,
		platformOS,
		architecture,
	)

	if err != nil {
		return model.CoreUpdateEvaluation{},
			err
	}

	defer rows.Close()

	var foundAny bool
	var foundPlatform bool

	for rows.Next() {
		var releaseOS string
		var releaseArchitecture string
		var releaseChannel string
		var approved bool
		var revoked bool
		var sha, downloadURL string

		if err := rows.Scan(
			&releaseOS,
			&releaseArchitecture,
			&releaseChannel,
			&approved,
			&revoked, &sha, &downloadURL,
		); err != nil {

			return model.CoreUpdateEvaluation{},
				err
		}

		foundAny = true

		if releaseOS != platformOS ||
			releaseArchitecture != architecture {

			continue
		}

		foundPlatform = true
		if !reviewedRuntimeArtifact(coreType, version, sha, downloadURL) {
			result.Blockers = appendUniqueString(result.Blockers, "unsupported_runtime_artifact")
		}

		result.ReleaseOS =
			releaseOS

		result.Architecture =
			releaseArchitecture

		result.ReleaseChannel =
			releaseChannel

		result.Approved =
			approved

		result.Revoked =
			revoked

		break
	}

	if err := rows.Err(); err != nil {
		return model.CoreUpdateEvaluation{},
			err
	}

	result.ReleaseFound =
		foundAny

	result.PlatformMatch =
		foundPlatform

	if !foundAny {
		result.Blockers =
			appendUniqueString(
				result.Blockers,
				"release_not_found",
			)

		return finalizeCoreUpdateEvaluation(
			result,
		), nil
	}

	if !foundPlatform {
		result.Blockers =
			appendUniqueString(
				result.Blockers,
				"wrong_platform",
			)

		return finalizeCoreUpdateEvaluation(
			result,
		), nil
	}

	if !result.Approved {
		result.Blockers =
			appendUniqueString(
				result.Blockers,
				"unapproved",
			)
	}

	if result.Revoked {
		result.Blockers =
			appendUniqueString(
				result.Blockers,
				"revoked",
			)
	}

	if !coreReleaseAllowedByPolicy(
		result.Policy,
		result.PinnedVersion,
		version,
		result.ReleaseChannel,
	) {
		if result.Policy == "pinned" {
			result.Blockers =
				appendUniqueString(
					result.Blockers,
					"pinned_mismatch",
				)
		} else {
			result.Blockers =
				appendUniqueString(
					result.Blockers,
					"wrong_channel",
				)
		}
	}

	if result.CurrentVersion == "" {
		result.NewerThanCurrent = true
	} else {
		result.NewerThanCurrent =
			compareCoreVersions(
				version,
				result.CurrentVersion,
			) > 0

		if !result.NewerThanCurrent {
			result.Blockers =
				appendUniqueString(
					result.Blockers,
					"not_newer",
				)
		}
	}

	return finalizeCoreUpdateEvaluation(
		result,
	), nil
}

func finalizeCoreUpdateEvaluation(
	result model.CoreUpdateEvaluation,
) model.CoreUpdateEvaluation {

	result.Eligible =
		len(result.Blockers) == 0

	return result
}

func appendUniqueString(
	values []string,
	value string,
) []string {

	for _, existing := range values {

		if existing == value {
			return values
		}
	}

	return append(
		values,
		value,
	)
}

func (p *Postgres) CreateCoreRolloutPlan(
	ctx context.Context,
	nodeID string,
	coreType string,
) (model.RolloutPlan, error) {
	return p.createCoreRolloutPlan(ctx, nodeID, coreType, "")
}

func (p *Postgres) createCoreRolloutPlan(ctx context.Context, nodeID, coreType, requestKey string) (model.RolloutPlan, error) {

	nodeID =
		strings.TrimSpace(nodeID)

	coreType =
		strings.TrimSpace(coreType)

	if nodeID == "" ||
		coreType == "" {

		return model.RolloutPlan{},
			errors.New(
				"node id and core type are required",
			)
	}

	updateStatus, err :=
		p.GetCoreUpdateStatus(
			ctx,
			nodeID,
			coreType,
		)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	defer tx.Rollback(ctx)

	var plan model.RolloutPlan

	var appliedGeneration int64

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			tenant_id::text,
			desired_generation,
			applied_generation
		FROM nodes
		WHERE id = $1
		FOR UPDATE
		`,
		nodeID,
	).Scan(
		&plan.TenantID,
		&plan.BaseGeneration,
		&appliedGeneration,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			ErrNotFound
	}

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	plan.NodeID = nodeID
	plan.CoreType = coreType

	plan.Policy =
		updateStatus.Policy

	plan.PinnedVersion =
		updateStatus.PinnedVersion

	plan.FromVersion =
		updateStatus.CurrentVersion

	plan.ProposedGeneration =
		plan.BaseGeneration + 1

	plan.TargetCoreReleaseID =
		updateStatus.CandidateReleaseID

	plan.TargetVersion =
		updateStatus.CandidateVersion

	plan.TargetChannel =
		updateStatus.CandidateChannel

	plan.Blockers =
		[]string{}

	if !updateStatus.CurrentHealthy {
		plan.Blockers =
			appendUniqueString(
				plan.Blockers,
				"node_unhealthy",
			)
	}

	if plan.BaseGeneration !=
		appliedGeneration {

		plan.Blockers =
			appendUniqueString(
				plan.Blockers,
				"node_not_converged",
			)
	}

	if !updateStatus.CandidateAvailable {
		plan.Blockers =
			appendUniqueString(
				plan.Blockers,
				"no_candidate",
			)
	} else if !updateStatus.UpdateAvailable {
		plan.Blockers =
			appendUniqueString(
				plan.Blockers,
				"no_update_available",
			)
	}

	var preview *model.DesiredState

	if len(plan.Blockers) == 0 {
		var raw []byte

		err = tx.QueryRow(
			ctx,
			`
			SELECT document
			FROM desired_states
			WHERE node_id = $1
			  AND generation = $2
			`,
			nodeID,
			plan.BaseGeneration,
		).Scan(
			&raw,
		)

		if errors.Is(err, pgx.ErrNoRows) {
			plan.Blockers =
				appendUniqueString(
					plan.Blockers,
					"no_desired_state",
				)
		} else if err != nil {
			return model.RolloutPlan{},
				err
		} else {
			var state model.DesiredState

			if err :=
				json.Unmarshal(
					raw,
					&state,
				); err != nil {

				return model.RolloutPlan{},
					fmt.Errorf(
						"decode current desired state: %w",
						err,
					)
			}

			state.Generation =
				plan.ProposedGeneration

			state.Core =
				model.CoreRelease{
					Type: coreType,

					Version: plan.TargetVersion,
				}

			preview = &state
		}
	}

	if len(plan.Blockers) == 0 {
		plan.Status =
			"planned"
	} else {
		plan.Status =
			"blocked"
	}

	plan.DesiredStatePreview =
		preview

	blockersJSON, err :=
		json.Marshal(
			plan.Blockers,
		)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	previewJSON := ""

	if preview != nil {
		raw, err :=
			json.Marshal(
				preview,
			)

		if err != nil {
			return model.RolloutPlan{},
				err
		}

		previewJSON =
			string(raw)
	}

	err = tx.QueryRow(
		ctx,
		`
		INSERT INTO rollout_plans(
			tenant_id,
			node_id,
			core_type,
			policy,
			pinned_version,
			base_generation,
			proposed_generation,
			from_version,
			target_core_release_id,
			target_version,
			target_channel,
			status,
			blockers,
			desired_state_preview,
			created_by,
			request_key
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			$3::text,
			$4::text,
			NULLIF($5::text, ''),
			$6::bigint,
			$7::bigint,
			NULLIF($8::text, ''),
			NULLIF($9::text, '')::uuid,
			NULLIF($10::text, ''),
			NULLIF($11::text, ''),
			$12::text,
			$13::jsonb,
			NULLIF($14::text, '')::jsonb,
			'control-plane',
			NULLIF($15::text, '')::uuid
		)
		RETURNING
			id::text,
			created_by,
			created_at,
			updated_at,
			expires_at
		`,
		plan.TenantID,
		plan.NodeID,
		plan.CoreType,
		plan.Policy,
		plan.PinnedVersion,
		plan.BaseGeneration,
		plan.ProposedGeneration,
		plan.FromVersion,
		plan.TargetCoreReleaseID,
		plan.TargetVersion,
		plan.TargetChannel,
		plan.Status,
		string(blockersJSON),
		previewJSON,
		requestKey,
	).Scan(
		&plan.ID,
		&plan.CreatedBy,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&plan.ExpiresAt,
	)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			'rollout_plan.created',
			'admin',
			'control-plane',
			jsonb_build_object(
				'rollout_plan_id', $3::text,
				'core_type', $4::text,
				'policy', $5::text,
				'base_generation', $6::bigint,
				'proposed_generation', $7::bigint,
				'from_version',
					NULLIF($8::text, ''),
				'target_version',
					NULLIF($9::text, ''),
				'target_channel',
					NULLIF($10::text, ''),
				'status', $11::text,
				'blockers', $12::jsonb
			)
		)
		`,
		plan.TenantID,
		plan.NodeID,
		plan.ID,
		plan.CoreType,
		plan.Policy,
		plan.BaseGeneration,
		plan.ProposedGeneration,
		plan.FromVersion,
		plan.TargetVersion,
		plan.TargetChannel,
		plan.Status,
		string(blockersJSON),
	)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.RolloutPlan{},
			err
	}

	return plan, nil
}

var (
	ErrRolloutPlanBlocked = errors.New("blocked rollout plan cannot be approved")

	ErrRolloutPlanAlreadyApproved = errors.New("rollout plan is already approved")

	ErrRolloutPlanNotApprovable = errors.New("rollout plan is not approvable")

	ErrRolloutPlanStale = errors.New("rollout plan is stale")

	ErrRolloutPlanTerminal = errors.New("rollout plan is already terminal")
)

type rolloutPlanRowScanner interface {
	Scan(dest ...any) error
}

func scanRolloutPlan(
	row rolloutPlanRowScanner,
) (model.RolloutPlan, error) {

	var plan model.RolloutPlan

	var blockersRaw []byte
	var previewRaw []byte

	err := row.Scan(
		&plan.ID,
		&plan.TenantID,
		&plan.NodeID,
		&plan.CoreType,
		&plan.Policy,
		&plan.PinnedVersion,
		&plan.BaseGeneration,
		&plan.ProposedGeneration,
		&plan.FromVersion,
		&plan.TargetCoreReleaseID,
		&plan.TargetVersion,
		&plan.TargetChannel,
		&plan.DeploymentID,
		&plan.OutcomeStatus,
		&plan.OutcomeAt,
		&plan.OutcomeReason,
		&plan.Status,
		&blockersRaw,
		&previewRaw,
		&plan.CreatedBy,
		&plan.ApprovedBy,
		&plan.ApprovedAt,
		&plan.ExecutedAt,
		&plan.CancelledAt,
		&plan.FailureReason,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&plan.ExpiresAt,
	)

	if err != nil {
		return model.RolloutPlan{}, err
	}

	plan.Blockers = []string{}

	if len(blockersRaw) > 0 {
		if err := json.Unmarshal(
			blockersRaw,
			&plan.Blockers,
		); err != nil {

			return model.RolloutPlan{},
				fmt.Errorf(
					"decode rollout blockers: %w",
					err,
				)
		}
	}

	if len(previewRaw) > 0 &&
		string(previewRaw) != "null" {

		var preview model.DesiredState

		if err := json.Unmarshal(
			previewRaw,
			&preview,
		); err != nil {

			return model.RolloutPlan{},
				fmt.Errorf(
					"decode rollout preview: %w",
					err,
				)
		}

		plan.DesiredStatePreview =
			&preview
	}

	return plan, nil
}

func rolloutPlanSelectSQL(
	forUpdate bool,
) string {

	query := `
		SELECT
			id::text,
			tenant_id::text,
			node_id::text,
			core_type,
			policy,
			COALESCE(pinned_version, ''),
			base_generation,
			proposed_generation,
			COALESCE(from_version, ''),
			COALESCE(target_core_release_id::text, ''),
			COALESCE(target_version, ''),
			COALESCE(target_channel, ''),
			COALESCE(deployment_id::text, ''),
			COALESCE(outcome_status, ''),
			outcome_at,
			COALESCE(outcome_reason, ''),
			status,
			blockers,
			desired_state_preview,
			created_by,
			COALESCE(approved_by, ''),
			approved_at,
			executed_at,
			cancelled_at,
			COALESCE(failure_reason, ''),
			created_at,
			updated_at,
			expires_at
		FROM rollout_plans
		WHERE id = $1::uuid
	`

	if forUpdate {
		query += " FOR UPDATE"
	}

	return query
}

func (p *Postgres) GetRolloutPlan(
	ctx context.Context,
	planID string,
) (model.RolloutPlan, error) {

	plan, err :=
		scanRolloutPlan(
			p.Pool.QueryRow(
				ctx,
				rolloutPlanSelectSQL(false),
				planID,
			),
		)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			ErrNotFound
	}

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	return plan, nil
}

func (p *Postgres) ApproveRolloutPlan(
	ctx context.Context,
	planID string,
) (model.RolloutPlan, error) {

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	defer tx.Rollback(ctx)

	plan, err :=
		scanRolloutPlan(
			tx.QueryRow(
				ctx,
				rolloutPlanSelectSQL(true),
				planID,
			),
		)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			ErrNotFound
	}

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	if rolloutPlanExpired(
		plan,
		time.Now().UTC(),
	) {
		if err := markRolloutPlanStaleTx(
			ctx,
			tx,
			&plan,
			"plan_expired",
		); err != nil {

			return model.RolloutPlan{},
				err
		}

		if err := tx.Commit(ctx); err != nil {
			return model.RolloutPlan{},
				err
		}

		return model.RolloutPlan{},
			fmt.Errorf(
				"%w: plan_expired",
				ErrRolloutPlanStale,
			)
	}

	switch plan.Status {
	case "blocked":
		return model.RolloutPlan{},
			ErrRolloutPlanBlocked

	case "approved":
		return model.RolloutPlan{},
			ErrRolloutPlanAlreadyApproved

	case "planned":
		// Continue with full stale-plan validation.

	default:
		return model.RolloutPlan{},
			ErrRolloutPlanNotApprovable
	}

	compatible, compatibilityErr := rolloutRuntimeCompatibleTx(ctx, tx, plan)
	if compatibilityErr != nil {
		return model.RolloutPlan{}, compatibilityErr
	}
	if !compatible {
		return model.RolloutPlan{}, ErrRolloutPlanStale
	}

	var desiredGeneration int64
	var appliedGeneration int64
	var healthy bool
	var currentVersion string
	var currentPolicy string
	var currentPinnedVersion string

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			n.desired_generation,
			n.applied_generation,
			COALESCE(nh.healthy, false),
			COALESCE(nh.core_version, ''),
			COALESCE(p.policy, 'pinned'),
			COALESCE(
				p.pinned_version,
				NULLIF(nh.core_version, ''),
				''
			)
		FROM nodes n
		LEFT JOIN node_health nh
			ON nh.node_id = n.id
			AND nh.core = $2
		LEFT JOIN node_core_update_policies p
			ON p.node_id = n.id
			AND p.core_type = $2
		WHERE n.id = $1::uuid
		`,
		plan.NodeID,
		plan.CoreType,
	).Scan(
		&desiredGeneration,
		&appliedGeneration,
		&healthy,
		&currentVersion,
		&currentPolicy,
		&currentPinnedVersion,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	if desiredGeneration != plan.BaseGeneration ||
		appliedGeneration != plan.BaseGeneration ||
		!healthy ||
		currentVersion != plan.FromVersion ||
		currentPolicy != plan.Policy ||
		currentPinnedVersion != plan.PinnedVersion {

		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	if plan.TargetCoreReleaseID == "" ||
		plan.TargetVersion == "" {

		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	var targetVersion string
	var targetChannel string
	var approved bool
	var revoked bool
	var platformMatch bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			cr.version,
			cr.channel,
			cr.approved,
			cr.revoked,

			(
				cr.architecture =
					COALESCE(n.architecture, '')
				AND
				cr.os =
					CASE
						WHEN lower(
							COALESCE(
								n.os_name,
								''
							)
						) IN (
							'ubuntu',
							'debian',
							'alpine',
							'centos',
							'rhel',
							'fedora',
							'rocky',
							'almalinux',
							'linux'
						)
						THEN 'linux'
						ELSE lower(
							COALESCE(
								n.os_name,
								''
							)
						)
					END
			)

		FROM core_releases cr
		JOIN nodes n
			ON n.id = $2::uuid
		WHERE cr.id = $1::uuid
		  AND cr.core_type = $3::text
		`,
		plan.TargetCoreReleaseID,
		plan.NodeID,
		plan.CoreType,
	).Scan(
		&targetVersion,
		&targetChannel,
		&approved,
		&revoked,
		&platformMatch,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	if targetVersion != plan.TargetVersion ||
		targetChannel != plan.TargetChannel ||
		!approved ||
		revoked ||
		!platformMatch {

		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	if !coreReleaseAllowedByPolicy(
		plan.Policy,
		plan.PinnedVersion,
		targetVersion,
		targetChannel,
	) {
		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	if plan.FromVersion != "" &&
		compareCoreVersions(
			targetVersion,
			plan.FromVersion,
		) <= 0 {

		return model.RolloutPlan{},
			ErrRolloutPlanStale
	}

	err = tx.QueryRow(
		ctx,
		`
		UPDATE rollout_plans
		SET
			status = 'approved',
			approved_by = 'control-plane',
			approved_at = now(),
			updated_at = now()
		WHERE id = $1::uuid
		RETURNING
			approved_at,
			updated_at
		`,
		plan.ID,
	).Scan(
		&plan.ApprovedAt,
		&plan.UpdatedAt,
	)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	plan.Status = "approved"
	plan.ApprovedBy = "control-plane"

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			'rollout_plan.approved',
			'admin',
			'control-plane',
			jsonb_build_object(
				'rollout_plan_id', $3::text,
				'core_type', $4::text,
				'base_generation', $5::bigint,
				'proposed_generation', $6::bigint,
				'from_version', $7::text,
				'target_version', $8::text,
				'target_channel', $9::text
			)
		)
		`,
		plan.TenantID,
		plan.NodeID,
		plan.ID,
		plan.CoreType,
		plan.BaseGeneration,
		plan.ProposedGeneration,
		plan.FromVersion,
		plan.TargetVersion,
		plan.TargetChannel,
	)

	if err != nil {
		return model.RolloutPlan{},
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.RolloutPlan{},
			err
	}

	return plan, nil
}

func (p *Postgres) CancelRolloutPlan(
	ctx context.Context,
	planID string,
) (model.RolloutPlan, bool, error) {

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	defer tx.Rollback(ctx)

	plan, err :=
		scanRolloutPlan(
			tx.QueryRow(
				ctx,
				rolloutPlanSelectSQL(true),
				planID,
			),
		)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			false,
			ErrNotFound
	}

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if plan.Status == "cancelled" {
		if err := tx.Commit(ctx); err != nil {
			return model.RolloutPlan{},
				false,
				err
		}

		return plan,
			false,
			nil
	}

	switch plan.Status {
	case "blocked",
		"planned",
		"approved":
		// Cancellation is allowed.

	default:
		return model.RolloutPlan{},
			false,
			ErrRolloutPlanTerminal
	}

	err = tx.QueryRow(
		ctx,
		`
		UPDATE rollout_plans
		SET
			status = 'cancelled',
			cancelled_at = now(),
			updated_at = now()
		WHERE id = $1::uuid
		RETURNING
			cancelled_at,
			updated_at
		`,
		plan.ID,
	).Scan(
		&plan.CancelledAt,
		&plan.UpdatedAt,
	)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	previousStatus :=
		plan.Status

	plan.Status =
		"cancelled"

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			'rollout_plan.cancelled',
			'admin',
			'control-plane',
			jsonb_build_object(
				'rollout_plan_id', $3::text,
				'previous_status', $4::text,
				'core_type', $5::text,
				'from_version',
					NULLIF($6::text, ''),
				'target_version',
					NULLIF($7::text, '')
			)
		)
		`,
		plan.TenantID,
		plan.NodeID,
		plan.ID,
		previousStatus,
		plan.CoreType,
		plan.FromVersion,
		plan.TargetVersion,
	)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	return plan,
		true,
		nil
}

var (
	ErrRolloutPlanNotExecutable = errors.New("rollout plan is not executable")

	ErrRolloutPlanAlreadyExecuted = errors.New("rollout plan is already executed")
)

func markRolloutPlanStaleTx(
	ctx context.Context,
	tx pgx.Tx,
	plan *model.RolloutPlan,
	reason string,
) error {

	reason =
		strings.TrimSpace(reason)

	err := tx.QueryRow(
		ctx,
		`
		UPDATE rollout_plans
		SET
			status = 'stale',
			failure_reason = $2,
			updated_at = now()
		WHERE id = $1::uuid
		RETURNING
			updated_at
		`,
		plan.ID,
		reason,
	).Scan(
		&plan.UpdatedAt,
	)

	if err != nil {
		return err
	}

	plan.Status = "stale"
	plan.FailureReason = reason

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			'rollout_plan.stale',
			'system',
			'rollout-executor',
			jsonb_build_object(
				'rollout_plan_id', $3::text,
				'core_type', $4::text,
				'base_generation', $5::bigint,
				'proposed_generation', $6::bigint,
				'from_version',
					NULLIF($7::text, ''),
				'target_version',
					NULLIF($8::text, ''),
				'reason', $9::text
			)
		)
		`,
		plan.TenantID,
		plan.NodeID,
		plan.ID,
		plan.CoreType,
		plan.BaseGeneration,
		plan.ProposedGeneration,
		plan.FromVersion,
		plan.TargetVersion,
		reason,
	)

	return err
}

func (p *Postgres) ExecuteRolloutPlan(
	ctx context.Context,
	planID string,
) (model.RolloutPlan, bool, error) {

	planID =
		strings.TrimSpace(planID)

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	defer tx.Rollback(ctx)

	plan, err :=
		scanRolloutPlan(
			tx.QueryRow(
				ctx,
				rolloutPlanSelectSQL(true),
				planID,
			),
		)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.RolloutPlan{},
			false,
			ErrNotFound
	}

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if plan.Status == "executed" {
		if err := tx.Commit(ctx); err != nil {
			return model.RolloutPlan{},
				false,
				err
		}

		return plan,
			false,
			nil
	}

	if rolloutPlanExpired(
		plan,
		time.Now().UTC(),
	) {
		if err := markRolloutPlanStaleTx(
			ctx,
			tx,
			&plan,
			"plan_expired",
		); err != nil {

			return model.RolloutPlan{},
				false,
				err
		}

		if err := tx.Commit(ctx); err != nil {
			return model.RolloutPlan{},
				false,
				err
		}

		return model.RolloutPlan{},
			false,
			fmt.Errorf(
				"%w: plan_expired",
				ErrRolloutPlanStale,
			)
	}

	_, err = tx.Exec(
		ctx,
		`
		SELECT pg_advisory_xact_lock(
			hashtextextended(
				$1::text,
				0
			)
		)
		`,
		plan.NodeID,
	)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if plan.Status != "approved" {
		return model.RolloutPlan{},
			false,
			ErrRolloutPlanNotExecutable
	}
	var agentUpdateRunning bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_fleet_jobs WHERE node_id=$1::uuid AND status='claimed')`, plan.NodeID).Scan(&agentUpdateRunning); err != nil {
		return model.RolloutPlan{}, false, err
	}
	if agentUpdateRunning {
		return model.RolloutPlan{}, false, ErrAgentFleetConflict
	}

	stale := func(
		reason string,
	) (model.RolloutPlan, bool, error) {

		if err := markRolloutPlanStaleTx(
			ctx,
			tx,
			&plan,
			reason,
		); err != nil {

			return model.RolloutPlan{},
				false,
				err
		}

		if err := tx.Commit(ctx); err != nil {
			return model.RolloutPlan{},
				false,
				err
		}

		return plan,
			false,
			fmt.Errorf(
				"%w: %s",
				ErrRolloutPlanStale,
				reason,
			)
	}

	compatible, compatibilityErr := rolloutRuntimeCompatibleTx(ctx, tx, plan)
	if compatibilityErr != nil {
		return model.RolloutPlan{}, false, compatibilityErr
	}
	if !compatible {
		return stale("runtime_compatibility_changed")
	}

	if plan.ApprovedAt == nil {
		return stale(
			"approved_timestamp_missing",
		)
	}

	if plan.ProposedGeneration !=
		plan.BaseGeneration+1 {

		return stale(
			"generation_sequence_changed",
		)
	}

	var desiredGeneration int64
	var appliedGeneration int64

	var healthy bool

	var currentVersion string
	var currentPolicy string
	var currentPinnedVersion string

	var platformOS string
	var architecture string

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			n.desired_generation,
			n.applied_generation,

			COALESCE(nh.healthy, false),
			COALESCE(nh.core_version, ''),

			COALESCE(p.policy, 'pinned'),

			COALESCE(
				p.pinned_version,
				NULLIF(nh.core_version, ''),
				''
			),

			CASE
				WHEN lower(
					COALESCE(
						n.os_name,
						''
					)
				) IN (
					'ubuntu',
					'debian',
					'alpine',
					'centos',
					'rhel',
					'fedora',
					'rocky',
					'almalinux',
					'linux'
				)
				THEN 'linux'
				ELSE lower(
					COALESCE(
						n.os_name,
						''
					)
				)
			END,

			COALESCE(
				n.architecture,
				''
			)

		FROM nodes n

		LEFT JOIN node_health nh
			ON nh.node_id = n.id
			AND nh.core = $2

		LEFT JOIN node_core_update_policies p
			ON p.node_id = n.id
			AND p.core_type = $2

		WHERE n.id = $1::uuid

		FOR UPDATE OF n
		`,
		plan.NodeID,
		plan.CoreType,
	).Scan(
		&desiredGeneration,
		&appliedGeneration,
		&healthy,
		&currentVersion,
		&currentPolicy,
		&currentPinnedVersion,
		&platformOS,
		&architecture,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return stale(
			"node_missing",
		)
	}

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if desiredGeneration !=
		plan.BaseGeneration {

		return stale(
			"desired_generation_changed",
		)
	}

	if appliedGeneration !=
		plan.BaseGeneration {

		return stale(
			"node_not_converged",
		)
	}

	if !healthy {
		return stale(
			"node_unhealthy",
		)
	}

	if currentVersion !=
		plan.FromVersion {

		return stale(
			"current_version_changed",
		)
	}

	if currentPolicy !=
		plan.Policy {

		return stale(
			"update_policy_changed",
		)
	}

	if currentPinnedVersion !=
		plan.PinnedVersion {

		return stale(
			"pinned_version_changed",
		)
	}

	if plan.TargetCoreReleaseID == "" ||
		plan.TargetVersion == "" {

		return stale(
			"target_release_missing",
		)
	}

	var target model.CoreReleaseRecord

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			id::text,
			core_type,
			version,
			os,
			architecture,
			download_url,
			lower(sha256),
			channel,
			upstream_prerelease,
			approved,
			revoked,
			COALESCE(approved_by, ''),
			COALESCE(approved_at::text, ''),
			created_at,
			updated_at

		FROM core_releases

		WHERE id = $1::uuid
		  AND core_type = $2::text
		`,
		plan.TargetCoreReleaseID,
		plan.CoreType,
	).Scan(
		&target.ID,
		&target.Type,
		&target.Version,
		&target.OS,
		&target.Architecture,
		&target.DownloadURL,
		&target.SHA256,
		&target.Channel,
		&target.UpstreamPrerelease,
		&target.Approved,
		&target.Revoked,
		&target.ApprovedBy,
		&target.ApprovedAt,
		&target.CreatedAt,
		&target.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return stale(
			"target_release_missing",
		)
	}

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if target.Version !=
		plan.TargetVersion {

		return stale(
			"target_version_changed",
		)
	}

	if target.Channel !=
		plan.TargetChannel {

		return stale(
			"target_channel_changed",
		)
	}

	if !target.Approved {
		return stale(
			"target_unapproved",
		)
	}

	if target.Revoked {
		return stale(
			"target_revoked",
		)
	}

	if target.OS != platformOS ||
		target.Architecture != architecture {

		return stale(
			"target_platform_mismatch",
		)
	}

	if !coreReleaseAllowedByPolicy(
		plan.Policy,
		plan.PinnedVersion,
		target.Version,
		target.Channel,
	) {
		return stale(
			"target_policy_mismatch",
		)
	}

	if plan.FromVersion != "" &&
		compareCoreVersions(
			target.Version,
			plan.FromVersion,
		) <= 0 {

		return stale(
			"target_not_newer",
		)
	}

	if plan.DesiredStatePreview == nil {
		return stale(
			"desired_state_preview_missing",
		)
	}

	state :=
		*plan.DesiredStatePreview

	if state.Generation !=
		plan.ProposedGeneration {

		return stale(
			"preview_generation_changed",
		)
	}

	if state.Core.Type !=
		plan.CoreType {

		return stale(
			"preview_core_type_changed",
		)
	}

	if state.Core.Version !=
		plan.TargetVersion {

		return stale(
			"preview_core_version_changed",
		)
	}

	state.Generation =
		plan.ProposedGeneration

	// Never trust download URL, SHA or release channel
	// stored in the rollout preview. Resolve them again
	// from the currently trusted Core Registry record.
	state.Core =
		model.CoreRelease{
			Type: target.Type,

			Version: target.Version,

			DownloadURL: target.DownloadURL,

			SHA256: target.SHA256,

			Channel: target.Channel,
		}

	if err := saveDesiredStateTx(
		ctx,
		tx,
		plan.NodeID,
		state,
		target.ID,
	); err != nil {

		return model.RolloutPlan{},
			false,
			err
	}

	var deploymentID string

	err = tx.QueryRow(
		ctx,
		`
		SELECT id::text
		FROM deployments
		WHERE node_id = $1::uuid
		  AND generation = $2::bigint
		`,
		plan.NodeID,
		plan.ProposedGeneration,
	).Scan(
		&deploymentID,
	)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	err = tx.QueryRow(
		ctx,
		`
		UPDATE rollout_plans
		SET
			status = 'executed',
			deployment_id = $2::uuid,
			outcome_status = 'pending',
			outcome_at = NULL,
			outcome_reason = NULL,
			executed_at = now(),
			failure_reason = NULL,
			updated_at = now()
		WHERE id = $1::uuid
		  AND status = 'approved'
		RETURNING
			deployment_id::text,
			outcome_status,
			executed_at,
			updated_at
		`,
		plan.ID,
		deploymentID,
	).Scan(
		&plan.DeploymentID,
		&plan.OutcomeStatus,
		&plan.ExecutedAt,
		&plan.UpdatedAt,
	)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	plan.Status =
		"executed"

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO audit_events(
			tenant_id,
			node_id,
			event_type,
			actor_type,
			actor_id,
			payload
		)
		VALUES(
			$1::uuid,
			$2::uuid,
			'rollout_plan.executed',
			'admin',
			'control-plane',
			jsonb_build_object(
				'rollout_plan_id', $3::text,
				'core_type', $4::text,
				'base_generation', $5::bigint,
				'generation', $6::bigint,
				'from_version', $7::text,
				'target_version', $8::text,
				'target_channel', $9::text,
				'core_release_id', $10::text,
							'deployment_id', $11::text
			)
		)
		`,
		plan.TenantID,
		plan.NodeID,
		plan.ID,
		plan.CoreType,
		plan.BaseGeneration,
		plan.ProposedGeneration,
		plan.FromVersion,
		plan.TargetVersion,
		plan.TargetChannel,
		target.ID,
		deploymentID,
	)

	if err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.RolloutPlan{},
			false,
			err
	}

	return plan,
		true,
		nil
}

func rolloutPlanExpired(
	plan model.RolloutPlan,
	now time.Time,
) bool {

	if plan.ExpiresAt.IsZero() {
		return false
	}

	return !plan.ExpiresAt.After(now)
}

type SweptRolloutPlan struct {
	ID                 string
	TenantID           string
	NodeID             string
	CoreType           string
	PreviousStatus     string
	BaseGeneration     int64
	ProposedGeneration int64
	FromVersion        string
	TargetVersion      string
	ExpiresAt          time.Time
}

func (p *Postgres) SweepExpiredRolloutPlans(
	ctx context.Context,
	limit int,
) ([]SweptRolloutPlan, error) {

	if limit < 1 || limit > 500 {
		return nil,
			errors.New(
				"rollout sweep limit must be between 1 and 500",
			)
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return nil, err
	}

	defer tx.Rollback(ctx)

	rows, err :=
		tx.Query(
			ctx,
			`
			SELECT
				id::text,
				tenant_id::text,
				node_id::text,
				core_type,
				status,
				base_generation,
				proposed_generation,
				COALESCE(from_version, ''),
				COALESCE(target_version, ''),
				expires_at
			FROM rollout_plans
			WHERE status IN (
				'planned',
				'approved'
			)
			  AND expires_at <= now()
			ORDER BY
				expires_at ASC,
				created_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
			`,
			limit,
		)

	if err != nil {
		return nil, err
	}

	var plans []SweptRolloutPlan

	for rows.Next() {
		var plan SweptRolloutPlan

		if err := rows.Scan(
			&plan.ID,
			&plan.TenantID,
			&plan.NodeID,
			&plan.CoreType,
			&plan.PreviousStatus,
			&plan.BaseGeneration,
			&plan.ProposedGeneration,
			&plan.FromVersion,
			&plan.TargetVersion,
			&plan.ExpiresAt,
		); err != nil {

			rows.Close()
			return nil, err
		}

		plans =
			append(
				plans,
				plan,
			)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}

	rows.Close()

	for _, plan := range plans {

		tag, err :=
			tx.Exec(
				ctx,
				`
				UPDATE rollout_plans
				SET
					status = 'stale',
					failure_reason = 'plan_expired',
					updated_at = now()
				WHERE id = $1::uuid
				  AND status = $2::text
				  AND expires_at <= now()
				`,
				plan.ID,
				plan.PreviousStatus,
			)

		if err != nil {
			return nil, err
		}

		if tag.RowsAffected() != 1 {
			return nil,
				fmt.Errorf(
					"expired rollout plan %s changed during sweep",
					plan.ID,
				)
		}

		_, err =
			tx.Exec(
				ctx,
				`
				INSERT INTO audit_events(
					tenant_id,
					node_id,
					event_type,
					actor_type,
					actor_id,
					payload
				)
				VALUES(
					$1::uuid,
					$2::uuid,
					'rollout_plan.stale',
					'system',
					'rollout-sweeper',
					jsonb_build_object(
						'rollout_plan_id',
							$3::text,
						'core_type',
							$4::text,
						'previous_status',
							$5::text,
						'base_generation',
							$6::bigint,
						'proposed_generation',
							$7::bigint,
						'from_version',
							NULLIF($8::text, ''),
						'target_version',
							NULLIF($9::text, ''),
						'expires_at',
							$10::timestamptz,
						'reason',
							'plan_expired'
					)
				)
				`,
				plan.TenantID,
				plan.NodeID,
				plan.ID,
				plan.CoreType,
				plan.PreviousStatus,
				plan.BaseGeneration,
				plan.ProposedGeneration,
				plan.FromVersion,
				plan.TargetVersion,
				plan.ExpiresAt,
			)

		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return plans, nil
}

type DetectedStuckDeployment struct {
	DeploymentID     string
	TenantID         string
	NodeID           string
	RolloutPlanID    string
	CoreType         string
	Generation       int64
	Status           string
	OperationalState string
	Reason           string
	AgeSeconds       int64
	SourceUpdatedAt  time.Time
	NodeOnline       bool
	EpisodeKey       string
}

func (p *Postgres) DetectStuckDeployments(
	ctx context.Context,
	limit int,
	observedAt time.Time,
) ([]DetectedStuckDeployment, error) {
	if limit < 1 || limit > 500 {
		return nil,
			errors.New(
				"deployment detection limit must be between 1 and 500",
			)
	}

	if observedAt.IsZero() {
		observedAt =
			time.Now().UTC()
	}

	pendingCutoff :=
		observedAt.Add(
			-deploymentPendingStuckAfter,
		)

	applyingCutoff :=
		observedAt.Add(
			-deploymentApplyingStuckAfter,
		)

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return nil, err
	}

	defer tx.Rollback(ctx)

	rows, err :=
		tx.Query(
			ctx,
			`
			SELECT
				d.id::text,
				n.tenant_id::text,
				d.node_id::text,
				COALESCE(
					rp.id::text,
					''
				),
				COALESCE(
					d.core_type,
					''
				),
				d.generation,
				d.status,
				d.updated_at,
				n.last_seen_at,

				d.id::text
					|| ':'
					|| d.status
					|| ':'
					|| to_char(
						d.updated_at
							AT TIME ZONE 'UTC',
						'YYYYMMDDHH24MISSUS'
					)

			FROM deployments d

			JOIN nodes n
				ON n.id = d.node_id

			LEFT JOIN rollout_plans rp
				ON rp.deployment_id = d.id

			WHERE n.status<>'retired' AND (
				(
					d.status = 'pending'
					AND d.updated_at <= $1::timestamptz
				)
				OR
				(
					d.status = 'applying'
					AND d.updated_at <= $2::timestamptz
				)
			)

			AND NOT EXISTS (
				SELECT 1
				FROM audit_events ae

				WHERE ae.event_type =
					'deployment.stuck_detected'

				  AND ae.payload->>'episode_key' =
					d.id::text
						|| ':'
						|| d.status
						|| ':'
						|| to_char(
							d.updated_at
								AT TIME ZONE 'UTC',
							'YYYYMMDDHH24MISSUS'
						)
			)

			ORDER BY
				d.updated_at ASC,
				d.id ASC

			LIMIT $3

			FOR UPDATE OF d
			SKIP LOCKED
			`,
			pendingCutoff,
			applyingCutoff,
			limit,
		)

	if err != nil {
		return nil, err
	}

	var candidates []DetectedStuckDeployment

	for rows.Next() {
		var item DetectedStuckDeployment
		var lastSeenAt *time.Time

		err := rows.Scan(
			&item.DeploymentID,
			&item.TenantID,
			&item.NodeID,
			&item.RolloutPlanID,
			&item.CoreType,
			&item.Generation,
			&item.Status,
			&item.SourceUpdatedAt,
			&lastSeenAt,
			&item.EpisodeKey,
		)

		if err != nil {
			rows.Close()
			return nil, err
		}

		age :=
			observedAt.Sub(
				item.SourceUpdatedAt,
			)

		if age < 0 {
			age = 0
		}

		item.AgeSeconds =
			int64(
				age / time.Second,
			)

		item.NodeOnline =
			lastSeenAt != nil &&
				!lastSeenAt.Before(
					observedAt.Add(
						-nodeOnlineWindow,
					),
				)

		item.OperationalState,
			_,
			item.Reason =
			deploymentOperationalState(
				item.Status,
				age,
			)

		candidates =
			append(
				candidates,
				item,
			)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}

	rows.Close()

	detected :=
		make(
			[]DetectedStuckDeployment,
			0,
			len(candidates),
		)

	for _, item := range candidates {

		tag, err :=
			tx.Exec(
				ctx,
				`
				INSERT INTO audit_events(
					tenant_id,
					node_id,
					event_type,
					actor_type,
					actor_id,
					payload
				)
				VALUES(
					$1::uuid,
					$2::uuid,
					'deployment.stuck_detected',
					'system',
					'deployment-observer',
					jsonb_build_object(
						'episode_key',
							$3::text,
						'deployment_id',
							$4::text,
						'rollout_plan_id',
							NULLIF(
								$5::text,
								''
							),
						'core_type',
							NULLIF(
								$6::text,
								''
							),
						'generation',
							$7::bigint,
						'status',
							$8::text,
						'operational_state',
							$9::text,
						'reason',
							$10::text,
						'age_seconds',
							$11::bigint,
						'source_updated_at',
							$12::timestamptz,
						'node_online',
							$13::boolean,
						'observed_at',
							$14::timestamptz
					)
				)
				ON CONFLICT DO NOTHING
				`,
				item.TenantID,
				item.NodeID,
				item.EpisodeKey,
				item.DeploymentID,
				item.RolloutPlanID,
				item.CoreType,
				item.Generation,
				item.Status,
				item.OperationalState,
				item.Reason,
				item.AgeSeconds,
				item.SourceUpdatedAt,
				item.NodeOnline,
				observedAt,
			)

		if err != nil {
			return nil, err
		}

		if tag.RowsAffected() == 1 {
			detected =
				append(
					detected,
					item,
				)
		}
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return nil, err
	}

	return detected, nil
}

var ErrInvalidDeploymentTransition = errors.New("invalid deployment transition")

func deploymentTransition(
	current string,
	next string,
) (
	changed bool,
	allowed bool,
) {
	if current == next {
		switch current {
		case "applying",
			"healthy",
			"failed",
			"rolled_back":
			return false, true
		}
	}

	switch current {
	case "pending":
		switch next {
		case "applying",
			"healthy",
			"failed",
			"rolled_back":
			return true, true
		}

	case "applying":
		switch next {
		case "healthy",
			"failed",
			"rolled_back":
			return true, true
		}

	case "healthy",
		"failed",
		"rolled_back":
		return false, false
	}

	return false, false
}

const (
	deploymentPendingStuckAfter  = 10 * time.Minute
	deploymentApplyingStuckAfter = 15 * time.Minute
	nodeOnlineWindow             = 2 * time.Minute
)

func deploymentOperationalState(
	status string,
	age time.Duration,
) (
	state string,
	stuck bool,
	reason string,
) {
	if age < 0 {
		age = 0
	}

	switch status {
	case "pending":
		if age >= deploymentPendingStuckAfter {
			return "stuck_pending",
				true,
				"deployment_timeout"
		}

		return "pending",
			false,
			""

	case "applying":
		if age >= deploymentApplyingStuckAfter {
			return "stuck_applying",
				true,
				"deployment_timeout"
		}

		return "applying",
			false,
			""

	case "healthy",
		"failed",
		"rolled_back":
		return "terminal",
			false,
			""

	default:
		return "unknown",
			false,
			""
	}
}
