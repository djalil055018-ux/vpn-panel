package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"vpn-platform/internal/model"
)

var (
	ErrRecoveryAttemptBlocked = errors.New("recovery attempt is blocked")

	ErrRecoveryAttemptAlreadyApproved = errors.New("recovery attempt is already approved")

	ErrRecoveryAttemptNotApprovable = errors.New("recovery attempt is not approvable")

	ErrRecoveryAttemptTerminal = errors.New("recovery attempt is terminal")

	ErrRecoveryAttemptStale = errors.New("recovery attempt is stale")

	ErrRecoveryAttemptConflict = errors.New("active recovery attempt already exists")
)

type recoveryAttemptFacts struct {
	TenantID string
	NodeID   string

	DesiredGeneration int64
	AppliedGeneration int64
	LastSeenAt        *time.Time

	SourceDeploymentID string
	SourceGeneration   int64
	SourceStatus       string
	SourceCoreType     string
	SourceReleaseID    string
	SourceRequested    string
	SourceApplied      string

	SourceExecutionID    string
	SourceExecutionEpoch int64

	LeaseState           string
	LeaseExecutionID     string
	LeaseExecutionEpoch  int64
	LeaseOwnerInstanceID string

	FenceState                    string
	FenceExecutionID              string
	FenceExecutionEpoch           int64
	FenceTargetOwnerInstanceID    string
	FenceAcknowledgedByInstanceID string

	HealthHealthy           bool
	HealthAppliedGeneration int64
	HealthCoreVersion       string
	HealthCheckedAt         *time.Time

	ReleaseType          string
	ReleaseVersion       string
	ReleaseChannel       string
	ReleaseApproved      bool
	ReleaseRevoked       bool
	ReleasePlatformMatch bool

	LiveReleaseID            string
	LiveReleaseType          string
	LiveReleaseVersion       string
	LiveReleaseChannel       string
	LiveReleaseApproved      bool
	LiveReleaseRevoked       bool
	LiveReleasePlatformMatch bool

	DesiredState *model.DesiredState
}

func loadRecoveryAttemptFactsTx(
	ctx context.Context,
	tx pgx.Tx,
	nodeID string,
	generation int64,
) (recoveryAttemptFacts, error) {
	var facts recoveryAttemptFacts

	err :=
		tx.QueryRow(
			ctx,
			`
			SELECT
				n.tenant_id::text,
				n.id::text,
				n.desired_generation,
				n.applied_generation,
				n.last_seen_at,

				d.id::text,
				d.generation,
				d.status,
				COALESCE(d.core_type, ''),
				COALESCE(d.core_release_id::text, ''),
				COALESCE(d.requested_core_version, ''),
				COALESCE(d.applied_core_version, ''),

				COALESCE(d.execution_id::text, ''),
				COALESCE(d.execution_epoch, 0),

				COALESCE(el.state, ''),
				COALESCE(el.execution_id::text, ''),
				COALESCE(el.execution_epoch, 0),
				COALESCE(el.owner_instance_id::text, ''),

				COALESCE(ef.state, ''),
				COALESCE(ef.execution_id::text, ''),
				COALESCE(ef.execution_epoch, 0),
				COALESCE(
					ef.target_owner_instance_id::text,
					''
				),
				COALESCE(
					ef.acknowledged_by_instance_id::text,
					''
				),

				COALESCE(nh.healthy, false),
				COALESCE(nh.applied_generation, 0),
				COALESCE(nh.core_version, ''),
				nh.checked_at,

				COALESCE(cr.core_type, ''),
				COALESCE(cr.version, ''),
				COALESCE(cr.channel, ''),
				COALESCE(cr.approved, false),
				COALESCE(cr.revoked, false),

				COALESCE(
					(
						cr.architecture =
							COALESCE(
								n.architecture,
								''
							)
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
					),
					false
				),

				COALESCE(live_cr.id::text, ''),
				COALESCE(live_cr.core_type, ''),
				COALESCE(live_cr.version, ''),
				COALESCE(live_cr.channel, ''),
				COALESCE(live_cr.approved, false),
				COALESCE(live_cr.revoked, false),

				COALESCE(
					(
						live_cr.architecture =
							COALESCE(
								n.architecture,
								''
							)
						AND
						live_cr.os =
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
					),
					false
				)

			FROM nodes n

			JOIN deployments d
				ON d.node_id = n.id
				AND d.generation = $2::bigint

			LEFT JOIN core_releases cr
				ON cr.id = d.core_release_id

			LEFT JOIN deployment_execution_leases el
				ON el.deployment_id = d.id
				AND el.node_id = d.node_id
				AND el.generation = d.generation
				AND el.execution_id = d.execution_id
				AND el.execution_epoch = d.execution_epoch

			LEFT JOIN LATERAL (
				SELECT
					f.state,
					f.execution_id,
					f.execution_epoch,
					f.target_owner_instance_id,
					f.acknowledged_by_instance_id
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
				WHERE node_id = n.id
				ORDER BY checked_at DESC
				LIMIT 1
			) nh ON true

			LEFT JOIN core_releases live_cr
				ON live_cr.core_type =
					COALESCE(
						d.core_type,
						''
					)
				AND live_cr.version =
					COALESCE(
						nh.core_version,
						''
					)
				AND live_cr.architecture =
					COALESCE(
						n.architecture,
						''
					)
				AND live_cr.os =
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

			WHERE n.id = $1::uuid

			FOR UPDATE OF n, d
			`,
			nodeID,
			generation,
		).Scan(
			&facts.TenantID,
			&facts.NodeID,
			&facts.DesiredGeneration,
			&facts.AppliedGeneration,
			&facts.LastSeenAt,

			&facts.SourceDeploymentID,
			&facts.SourceGeneration,
			&facts.SourceStatus,
			&facts.SourceCoreType,
			&facts.SourceReleaseID,
			&facts.SourceRequested,
			&facts.SourceApplied,

			&facts.SourceExecutionID,
			&facts.SourceExecutionEpoch,

			&facts.LeaseState,
			&facts.LeaseExecutionID,
			&facts.LeaseExecutionEpoch,
			&facts.LeaseOwnerInstanceID,

			&facts.FenceState,
			&facts.FenceExecutionID,
			&facts.FenceExecutionEpoch,
			&facts.FenceTargetOwnerInstanceID,
			&facts.FenceAcknowledgedByInstanceID,

			&facts.HealthHealthy,
			&facts.HealthAppliedGeneration,
			&facts.HealthCoreVersion,
			&facts.HealthCheckedAt,

			&facts.ReleaseType,
			&facts.ReleaseVersion,
			&facts.ReleaseChannel,
			&facts.ReleaseApproved,
			&facts.ReleaseRevoked,
			&facts.ReleasePlatformMatch,

			&facts.LiveReleaseID,
			&facts.LiveReleaseType,
			&facts.LiveReleaseVersion,
			&facts.LiveReleaseChannel,
			&facts.LiveReleaseApproved,
			&facts.LiveReleaseRevoked,
			&facts.LiveReleasePlatformMatch,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return recoveryAttemptFacts{},
			ErrNotFound
	}

	if err != nil {
		return recoveryAttemptFacts{},
			err
	}

	var raw []byte

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT document
			FROM desired_states
			WHERE node_id = $1::uuid
			  AND generation = $2::bigint
			`,
			nodeID,
			generation,
		).Scan(
			&raw,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return facts, nil
	}

	if err != nil {
		return recoveryAttemptFacts{},
			err
	}

	var state model.DesiredState

	if err :=
		json.Unmarshal(
			raw,
			&state,
		); err != nil {

		return recoveryAttemptFacts{},
			fmt.Errorf(
				"decode source desired state: %w",
				err,
			)
	}

	facts.DesiredState =
		&state

	return facts, nil
}

func recoveryAttemptBlockers(
	facts recoveryAttemptFacts,
	now time.Time,
) []string {
	blockers :=
		make(
			[]string,
			0,
		)

	physicallyFenced :=
		recoverySourcePhysicallyFenced(
			facts,
		)

	switch facts.SourceStatus {
	case "rolled_back":
		// Existing safe rollback recovery path.

	case "pending",
		"applying":

		if !physicallyFenced {
			blockers =
				appendUniqueString(
					blockers,
					"source_requires_physical_fence",
				)
		}

	default:
		blockers =
			appendUniqueString(
				blockers,
				"source_status_not_recoverable",
			)
	}

	if facts.DesiredGeneration !=
		facts.SourceGeneration {

		blockers =
			appendUniqueString(
				blockers,
				"source_not_current_desired",
			)
	}

	if facts.AppliedGeneration >=
		facts.SourceGeneration {

		blockers =
			appendUniqueString(
				blockers,
				"source_already_applied",
			)
	}

	nodeOnline :=
		facts.LastSeenAt != nil &&
			!facts.LastSeenAt.Before(
				now.Add(
					-nodeOnlineWindow,
				),
			)

	if !nodeOnline {
		blockers =
			appendUniqueString(
				blockers,
				"node_offline",
			)
	}

	healthFresh :=
		facts.HealthCheckedAt != nil &&
			!facts.HealthCheckedAt.Before(
				now.Add(
					-nodeOnlineWindow,
				),
			)

	if !healthFresh {
		blockers =
			appendUniqueString(
				blockers,
				"node_health_stale",
			)
	} else {
		if !facts.HealthHealthy {
			blockers =
				appendUniqueString(
					blockers,
					"node_unhealthy",
				)
		}

		if facts.HealthAppliedGeneration !=
			facts.AppliedGeneration {

			blockers =
				appendUniqueString(
					blockers,
					"health_generation_mismatch",
				)
		}
	}

	if facts.SourceStatus == "rolled_back" {
		if facts.SourceApplied == "" {
			blockers =
				appendUniqueString(
					blockers,
					"rollback_applied_version_missing",
				)
		} else if healthFresh &&
			facts.HealthCoreVersion !=
				facts.SourceApplied {

			blockers =
				appendUniqueString(
					blockers,
					"rollback_core_version_mismatch",
				)
		}

		if facts.SourceReleaseID == "" {
			blockers =
				appendUniqueString(
					blockers,
					"source_release_missing",
				)
		} else {
			if facts.ReleaseType !=
				facts.SourceCoreType {

				blockers =
					appendUniqueString(
						blockers,
						"source_release_core_mismatch",
					)
			}

			if facts.ReleaseVersion !=
				facts.SourceRequested {

				blockers =
					appendUniqueString(
						blockers,
						"source_release_version_mismatch",
					)
			}

			if !facts.ReleaseApproved {
				blockers =
					appendUniqueString(
						blockers,
						"source_release_unapproved",
					)
			}

			if facts.ReleaseRevoked {
				blockers =
					appendUniqueString(
						blockers,
						"source_release_revoked",
					)
			}

			if !facts.ReleasePlatformMatch {
				blockers =
					appendUniqueString(
						blockers,
						"source_release_platform_mismatch",
					)
			}
		}
	}

	if (facts.SourceStatus == "pending" ||
		facts.SourceStatus == "applying") &&
		physicallyFenced {

		if facts.HealthCoreVersion == "" {
			blockers =
				appendUniqueString(
					blockers,
					"live_core_version_missing",
				)
		}

		if facts.LiveReleaseID == "" {
			blockers =
				appendUniqueString(
					blockers,
					"live_release_missing",
				)
		} else {
			if facts.LiveReleaseType !=
				facts.SourceCoreType {

				blockers =
					appendUniqueString(
						blockers,
						"live_release_core_mismatch",
					)
			}

			if facts.LiveReleaseVersion !=
				facts.HealthCoreVersion {

				blockers =
					appendUniqueString(
						blockers,
						"live_release_version_mismatch",
					)
			}

			if !facts.LiveReleaseApproved {
				blockers =
					appendUniqueString(
						blockers,
						"live_release_unapproved",
					)
			}

			if facts.LiveReleaseRevoked {
				blockers =
					appendUniqueString(
						blockers,
						"live_release_revoked",
					)
			}

			if !facts.LiveReleasePlatformMatch {
				blockers =
					appendUniqueString(
						blockers,
						"live_release_platform_mismatch",
					)
			}
		}
	}

	if facts.DesiredState == nil {
		blockers =
			appendUniqueString(
				blockers,
				"source_desired_state_missing",
			)
	} else {
		if facts.DesiredState.Generation !=
			facts.SourceGeneration {

			blockers =
				appendUniqueString(
					blockers,
					"source_desired_generation_mismatch",
				)
		}

		if facts.DesiredState.Core.Type !=
			facts.SourceCoreType {

			blockers =
				appendUniqueString(
					blockers,
					"source_desired_core_mismatch",
				)
		}

		if facts.DesiredState.Core.Version !=
			facts.SourceRequested {

			blockers =
				appendUniqueString(
					blockers,
					"source_desired_version_mismatch",
				)
		}
	}

	return blockers
}
func expireRecoveryAttemptsForNodeTx(
	ctx context.Context,
	tx pgx.Tx,
	nodeID string,
) error {
	rows, err :=
		tx.Query(
			ctx,
			`
			UPDATE recovery_attempts
			SET
				status = 'stale',
				failure_reason = 'plan_expired',
				updated_at = now()
			WHERE node_id = $1::uuid
			  AND status IN (
				'planned',
				'approved'
			  )
			  AND expires_at <= now()
			RETURNING
				id::text,
				tenant_id::text,
				source_deployment_id::text,
				source_generation,
				proposed_generation,
				core_type
			`,
			nodeID,
		)

	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		var id string
		var tenantID string
		var sourceDeploymentID string
		var sourceGeneration int64
		var proposedGeneration int64
		var coreType string

		if err :=
			rows.Scan(
				&id,
				&tenantID,
				&sourceDeploymentID,
				&sourceGeneration,
				&proposedGeneration,
				&coreType,
			); err != nil {

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
					payload
				)
				VALUES(
					$1::uuid,
					$2::uuid,
					'recovery_attempt.stale',
					'system',
					'recovery-planner',
					jsonb_build_object(
						'recovery_attempt_id',
							$3::text,
						'source_deployment_id',
							$4::text,
						'source_generation',
							$5::bigint,
						'proposed_generation',
							$6::bigint,
						'core_type',
							$7::text,
						'reason',
							'plan_expired'
					)
				)
				`,
				tenantID,
				nodeID,
				id,
				sourceDeploymentID,
				sourceGeneration,
				proposedGeneration,
				coreType,
			)

		if err != nil {
			return err
		}
	}

	return rows.Err()
}

func (p *Postgres) CreateRecoveryAttempt(
	ctx context.Context,
	nodeID string,
	generation int64,
) (model.RecoveryAttempt, error) {
	nodeID =
		strings.TrimSpace(
			nodeID,
		)

	if nodeID == "" ||
		generation < 1 {

		return model.RecoveryAttempt{},
			errors.New(
				"node id and generation are required",
			)
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	defer tx.Rollback(ctx)

	if err :=
		expireRecoveryAttemptsForNodeTx(
			ctx,
			tx,
			nodeID,
		); err != nil {

		return model.RecoveryAttempt{},
			err
	}

	_, err =
		tx.Exec(
			ctx,
			`
			SELECT pg_advisory_xact_lock(
				hashtextextended(
					$1::text,
					0
				)
			)
			`,
			nodeID,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	facts, err :=
		loadRecoveryAttemptFactsTx(
			ctx,
			tx,
			nodeID,
			generation,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	now :=
		time.Now().UTC()

	target :=
		recoveryAttemptTargetForFacts(
			facts,
		)

	plan :=
		model.RecoveryAttempt{
			TenantID:               facts.TenantID,
			NodeID:                 facts.NodeID,
			SourceDeploymentID:     facts.SourceDeploymentID,
			SourceGeneration:       facts.SourceGeneration,
			SourceDeploymentStatus: facts.SourceStatus,
			BaseDesiredGeneration:  facts.DesiredGeneration,
			BaseAppliedGeneration:  facts.AppliedGeneration,
			ProposedGeneration:     facts.DesiredGeneration + 1,
			CoreType:               facts.SourceCoreType,
			TargetCoreReleaseID:    target.ID,
			TargetVersion:          target.Version,
			TargetChannel:          target.Channel,
			Blockers:               recoveryAttemptBlockers(facts, now),
			CreatedBy:              "control-plane",
		}

	if len(plan.Blockers) == 0 {
		if target.ID == "" ||
			target.Type == "" ||
			target.Version == "" {

			plan.Blockers =
				appendUniqueString(
					plan.Blockers,
					"recovery_target_missing",
				)

			plan.Status =
				"blocked"
		} else {
			plan.Status =
				"planned"

			state :=
				*facts.DesiredState

			state.Generation =
				plan.ProposedGeneration

			state.Core =
				model.CoreRelease{
					Type:    target.Type,
					Version: target.Version,
				}

			plan.DesiredStatePreview =
				&state
		}
	} else {
		plan.Status =
			"blocked"
	}

	blockersRaw, err :=
		json.Marshal(
			plan.Blockers,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	previewRaw := ""

	if plan.DesiredStatePreview != nil {
		raw, err :=
			json.Marshal(
				plan.DesiredStatePreview,
			)

		if err != nil {
			return model.RecoveryAttempt{},
				err
		}

		previewRaw =
			string(raw)
	}

	err =
		tx.QueryRow(
			ctx,
			`
			INSERT INTO recovery_attempts(
				tenant_id,
				node_id,
				source_deployment_id,
				source_generation,
				source_deployment_status,
				base_desired_generation,
				base_applied_generation,
				proposed_generation,
				core_type,
				target_core_release_id,
				target_version,
				target_channel,
				status,
				blockers,
				desired_state_preview,
				created_by
			)
			VALUES(
				$1::uuid,
				$2::uuid,
				$3::uuid,
				$4::bigint,
				$5::text,
				$6::bigint,
				$7::bigint,
				$8::bigint,
				$9::text,
				NULLIF($10::text, '')::uuid,
				NULLIF($11::text, ''),
				NULLIF($12::text, ''),
				$13::text,
				$14::jsonb,
				NULLIF($15::text, '')::jsonb,
				'control-plane'
			)
			RETURNING
				id::text,
				created_at,
				updated_at,
				expires_at
			`,
			plan.TenantID,
			plan.NodeID,
			plan.SourceDeploymentID,
			plan.SourceGeneration,
			plan.SourceDeploymentStatus,
			plan.BaseDesiredGeneration,
			plan.BaseAppliedGeneration,
			plan.ProposedGeneration,
			plan.CoreType,
			plan.TargetCoreReleaseID,
			plan.TargetVersion,
			plan.TargetChannel,
			plan.Status,
			string(blockersRaw),
			previewRaw,
		).Scan(
			&plan.ID,
			&plan.CreatedAt,
			&plan.UpdatedAt,
			&plan.ExpiresAt,
		)

	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(
			err,
			&pgErr,
		) &&
			pgErr.Code == "23505" {

			return model.RecoveryAttempt{},
				ErrRecoveryAttemptConflict
		}

		return model.RecoveryAttempt{},
			err
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
				'recovery_attempt.created',
				'admin',
				'control-plane',
				jsonb_build_object(
					'recovery_attempt_id',
						$3::text,
					'source_deployment_id',
						$4::text,
					'source_generation',
						$5::bigint,
					'proposed_generation',
						$6::bigint,
					'status',
						$7::text,
					'blockers',
						$8::jsonb
				)
			)
			`,
			plan.TenantID,
			plan.NodeID,
			plan.ID,
			plan.SourceDeploymentID,
			plan.SourceGeneration,
			plan.ProposedGeneration,
			plan.Status,
			string(blockersRaw),
		)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.RecoveryAttempt{},
			err
	}

	return plan, nil
}

func recoveryAttemptSelectSQL(
	forUpdate bool,
) string {
	query :=
		`
		SELECT
			id::text,
			tenant_id::text,
			node_id::text,
			source_deployment_id::text,
			source_generation,
			source_deployment_status,
			base_desired_generation,
			base_applied_generation,
			proposed_generation,
			core_type,
			COALESCE(target_core_release_id::text, ''),
			COALESCE(target_version, ''),
			COALESCE(target_channel, ''),
			status,
			blockers::text,
			COALESCE(desired_state_preview::text, ''),
			COALESCE(deployment_id::text, ''),
			created_by,
			COALESCE(approved_by, ''),
			approved_at,
			executed_at,
			cancelled_at,
			COALESCE(failure_reason, ''),
			created_at,
			updated_at,
			expires_at
		FROM recovery_attempts
		WHERE id = $1::uuid
		`

	if forUpdate {
		query +=
			" FOR UPDATE"
	}

	return query
}

func scanRecoveryAttempt(
	row pgx.Row,
) (model.RecoveryAttempt, error) {
	var plan model.RecoveryAttempt
	var blockersRaw string
	var previewRaw string

	err :=
		row.Scan(
			&plan.ID,
			&plan.TenantID,
			&plan.NodeID,
			&plan.SourceDeploymentID,
			&plan.SourceGeneration,
			&plan.SourceDeploymentStatus,
			&plan.BaseDesiredGeneration,
			&plan.BaseAppliedGeneration,
			&plan.ProposedGeneration,
			&plan.CoreType,
			&plan.TargetCoreReleaseID,
			&plan.TargetVersion,
			&plan.TargetChannel,
			&plan.Status,
			&blockersRaw,
			&previewRaw,
			&plan.DeploymentID,
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
		return model.RecoveryAttempt{},
			err
	}

	if err :=
		json.Unmarshal(
			[]byte(blockersRaw),
			&plan.Blockers,
		); err != nil {

		return model.RecoveryAttempt{},
			err
	}

	if previewRaw != "" {
		var state model.DesiredState

		if err :=
			json.Unmarshal(
				[]byte(previewRaw),
				&state,
			); err != nil {

			return model.RecoveryAttempt{},
				err
		}

		plan.DesiredStatePreview =
			&state
	}

	return plan, nil
}

func (p *Postgres) GetRecoveryAttempt(
	ctx context.Context,
	id string,
) (model.RecoveryAttempt, error) {
	plan, err :=
		scanRecoveryAttempt(
			p.Pool.QueryRow(
				ctx,
				recoveryAttemptSelectSQL(false),
				strings.TrimSpace(id),
			),
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.RecoveryAttempt{},
			ErrNotFound
	}

	return plan, err
}

func recoveryAttemptExpired(
	plan model.RecoveryAttempt,
	now time.Time,
) bool {
	return !plan.ExpiresAt.IsZero() &&
		!plan.ExpiresAt.After(now)
}

func markRecoveryAttemptStaleTx(
	ctx context.Context,
	tx pgx.Tx,
	plan *model.RecoveryAttempt,
	reason string,
) error {
	reason =
		strings.TrimSpace(reason)

	err :=
		tx.QueryRow(
			ctx,
			`
			UPDATE recovery_attempts
			SET
				status = 'stale',
				failure_reason = $2::text,
				updated_at = now()
			WHERE id = $1::uuid
			RETURNING updated_at
			`,
			plan.ID,
			reason,
		).Scan(
			&plan.UpdatedAt,
		)

	if err != nil {
		return err
	}

	plan.Status =
		"stale"

	plan.FailureReason =
		reason

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
				'recovery_attempt.stale',
				'system',
				'recovery-planner',
				jsonb_build_object(
					'recovery_attempt_id',
						$3::text,
					'source_deployment_id',
						$4::text,
					'source_generation',
						$5::bigint,
					'proposed_generation',
						$6::bigint,
					'reason',
						$7::text
				)
			)
			`,
			plan.TenantID,
			plan.NodeID,
			plan.ID,
			plan.SourceDeploymentID,
			plan.SourceGeneration,
			plan.ProposedGeneration,
			reason,
		)

	return err
}

func recoveryAttemptStaleReason(
	plan model.RecoveryAttempt,
	facts recoveryAttemptFacts,
	now time.Time,
) string {
	blockers :=
		recoveryAttemptBlockers(
			facts,
			now,
		)

	if len(blockers) > 0 {
		return blockers[0]
	}

	if plan.SourceDeploymentID !=
		facts.SourceDeploymentID {

		return "source_deployment_changed"
	}

	if plan.SourceGeneration !=
		facts.SourceGeneration {

		return "source_generation_changed"
	}

	if plan.SourceDeploymentStatus !=
		facts.SourceStatus {

		return "source_status_changed"
	}

	if plan.BaseDesiredGeneration !=
		facts.DesiredGeneration {

		return "desired_generation_changed"
	}

	if plan.BaseAppliedGeneration !=
		facts.AppliedGeneration {

		return "applied_generation_changed"
	}

	if plan.ProposedGeneration !=
		plan.BaseDesiredGeneration+1 {

		return "generation_sequence_changed"
	}

	if plan.CoreType !=
		facts.SourceCoreType {

		return "core_type_changed"
	}

	target :=
		recoveryAttemptTargetForFacts(
			facts,
		)

	if target.ID == "" {
		return "target_release_missing"
	}

	if plan.TargetCoreReleaseID !=
		target.ID {

		return "target_release_changed"
	}

	if plan.TargetVersion !=
		target.Version {

		return "target_version_changed"
	}

	if plan.TargetChannel !=
		target.Channel {

		return "target_channel_changed"
	}

	if plan.DesiredStatePreview == nil ||
		facts.DesiredState == nil {

		return "desired_state_preview_missing"
	}

	if plan.DesiredStatePreview.Generation !=
		plan.ProposedGeneration {

		return "preview_generation_changed"
	}

	if plan.DesiredStatePreview.Core.Type !=
		target.Type {

		return "preview_core_type_changed"
	}

	if plan.DesiredStatePreview.Core.Version !=
		target.Version {

		return "preview_core_version_changed"
	}

	if !reflect.DeepEqual(
		plan.DesiredStatePreview.Services,
		facts.DesiredState.Services,
	) {
		return "preview_services_changed"
	}

	return ""
}
func (p *Postgres) ApproveRecoveryAttempt(
	ctx context.Context,
	id string,
) (model.RecoveryAttempt, error) {
	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	defer tx.Rollback(ctx)

	plan, err :=
		scanRecoveryAttempt(
			tx.QueryRow(
				ctx,
				recoveryAttemptSelectSQL(true),
				strings.TrimSpace(id),
			),
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.RecoveryAttempt{},
			ErrNotFound
	}

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	if recoveryAttemptExpired(
		plan,
		time.Now().UTC(),
	) {
		if err :=
			markRecoveryAttemptStaleTx(
				ctx,
				tx,
				&plan,
				"plan_expired",
			); err != nil {

			return model.RecoveryAttempt{},
				err
		}

		if err :=
			tx.Commit(ctx); err != nil {

			return model.RecoveryAttempt{},
				err
		}

		return model.RecoveryAttempt{},
			fmt.Errorf(
				"%w: plan_expired",
				ErrRecoveryAttemptStale,
			)
	}

	switch plan.Status {
	case "blocked":
		return model.RecoveryAttempt{},
			ErrRecoveryAttemptBlocked

	case "approved":
		return model.RecoveryAttempt{},
			ErrRecoveryAttemptAlreadyApproved

	case "planned":
		// Continue.

	default:
		return model.RecoveryAttempt{},
			ErrRecoveryAttemptNotApprovable
	}

	_, err =
		tx.Exec(
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
		return model.RecoveryAttempt{},
			err
	}

	facts, err :=
		loadRecoveryAttemptFactsTx(
			ctx,
			tx,
			plan.NodeID,
			plan.SourceGeneration,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	if reason :=
		recoveryAttemptStaleReason(
			plan,
			facts,
			time.Now().UTC(),
		); reason != "" {

		if err :=
			markRecoveryAttemptStaleTx(
				ctx,
				tx,
				&plan,
				reason,
			); err != nil {

			return model.RecoveryAttempt{},
				err
		}

		if err :=
			tx.Commit(ctx); err != nil {

			return model.RecoveryAttempt{},
				err
		}

		return model.RecoveryAttempt{},
			fmt.Errorf(
				"%w: %s",
				ErrRecoveryAttemptStale,
				reason,
			)
	}

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE recovery_attempts
			SET
				status = 'approved',
				approved_by = 'control-plane',
				approved_at = now(),
				updated_at = now()
			WHERE id = $1::uuid
			  AND status = 'planned'
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
		return model.RecoveryAttempt{},
			err
	}

	plan.Status =
		"approved"

	plan.ApprovedBy =
		"control-plane"

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
				'recovery_attempt.approved',
				'admin',
				'control-plane',
				jsonb_build_object(
					'recovery_attempt_id',
						$3::text,
					'source_deployment_id',
						$4::text,
					'source_generation',
						$5::bigint,
					'proposed_generation',
						$6::bigint,
					'target_version',
						$7::text
				)
			)
			`,
			plan.TenantID,
			plan.NodeID,
			plan.ID,
			plan.SourceDeploymentID,
			plan.SourceGeneration,
			plan.ProposedGeneration,
			plan.TargetVersion,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.RecoveryAttempt{},
			err
	}

	return plan, nil
}

func (p *Postgres) CancelRecoveryAttempt(
	ctx context.Context,
	id string,
) (model.RecoveryAttempt, bool, error) {
	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.RecoveryAttempt{},
			false,
			err
	}

	defer tx.Rollback(ctx)

	plan, err :=
		scanRecoveryAttempt(
			tx.QueryRow(
				ctx,
				recoveryAttemptSelectSQL(true),
				strings.TrimSpace(id),
			),
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.RecoveryAttempt{},
			false,
			ErrNotFound
	}

	if err != nil {
		return model.RecoveryAttempt{},
			false,
			err
	}

	if plan.Status == "cancelled" {
		if err :=
			tx.Commit(ctx); err != nil {

			return model.RecoveryAttempt{},
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
		// Allowed.

	default:
		return model.RecoveryAttempt{},
			false,
			ErrRecoveryAttemptTerminal
	}

	previousStatus :=
		plan.Status

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE recovery_attempts
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
		return model.RecoveryAttempt{},
			false,
			err
	}

	plan.Status =
		"cancelled"

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
				'recovery_attempt.cancelled',
				'admin',
				'control-plane',
				jsonb_build_object(
					'recovery_attempt_id',
						$3::text,
					'source_deployment_id',
						$4::text,
					'source_generation',
						$5::bigint,
					'proposed_generation',
						$6::bigint,
					'previous_status',
						$7::text
				)
			)
			`,
			plan.TenantID,
			plan.NodeID,
			plan.ID,
			plan.SourceDeploymentID,
			plan.SourceGeneration,
			plan.ProposedGeneration,
			previousStatus,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			false,
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.RecoveryAttempt{},
			false,
			err
	}

	return plan,
		true,
		nil
}
