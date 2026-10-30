package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

var ErrRecoveryAttemptNotExecutable = errors.New(
	"recovery attempt is not executable",
)

func (p *Postgres) ExecuteRecoveryAttempt(
	ctx context.Context,
	id string,
) (
	model.RecoveryAttempt,
	bool,
	error,
) {
	id =
		strings.TrimSpace(id)

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
				id,
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

	if plan.Status == "executed" {
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
			false,
			fmt.Errorf(
				"%w: plan_expired",
				ErrRecoveryAttemptStale,
			)
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
			false,
			err
	}

	if plan.Status != "approved" {
		return model.RecoveryAttempt{},
			false,
			ErrRecoveryAttemptNotExecutable
	}

	stale :=
		func(
			reason string,
		) (
			model.RecoveryAttempt,
			bool,
			error,
		) {
			if err :=
				markRecoveryAttemptStaleTx(
					ctx,
					tx,
					&plan,
					reason,
				); err != nil {

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
				false,
				fmt.Errorf(
					"%w: %s",
					ErrRecoveryAttemptStale,
					reason,
				)
		}

	if plan.ApprovedAt == nil {
		return stale(
			"approved_timestamp_missing",
		)
	}

	facts, err :=
		loadRecoveryAttemptFactsTx(
			ctx,
			tx,
			plan.NodeID,
			plan.SourceGeneration,
		)

	if errors.Is(
		err,
		ErrNotFound,
	) {
		return stale(
			"source_deployment_missing",
		)
	}

	if err != nil {
		return model.RecoveryAttempt{},
			false,
			err
	}

	if reason :=
		recoveryAttemptStaleReason(
			plan,
			facts,
			time.Now().UTC(),
		); reason != "" {

		return stale(reason)
	}

	if plan.ProposedGeneration !=
		plan.SourceGeneration+1 {

		return stale(
			"generation_sequence_changed",
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

	if plan.TargetCoreReleaseID == "" {
		return stale(
			"target_release_missing",
		)
	}

	var target model.CoreReleaseRecord
	var platformMatch bool

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				cr.id::text,
				cr.core_type,
				cr.version,
				cr.os,
				cr.architecture,
				cr.download_url,
				lower(cr.sha256),
				cr.channel,
				cr.upstream_prerelease,
				cr.approved,
				cr.revoked,
				COALESCE(
					cr.approved_by,
					''
				),
				COALESCE(
					cr.approved_at::text,
					''
				),
				cr.created_at,
				cr.updated_at,

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
				)

			FROM core_releases cr

			JOIN nodes n
				ON n.id = $2::uuid

			WHERE cr.id = $1::uuid
			  AND cr.core_type = $3::text

			FOR SHARE OF cr
			`,
			plan.TargetCoreReleaseID,
			plan.NodeID,
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
			&platformMatch,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return stale(
			"target_release_missing",
		)
	}

	if err != nil {
		return model.RecoveryAttempt{},
			false,
			err
	}

	if target.Type !=
		plan.CoreType {

		return stale(
			"target_core_type_changed",
		)
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

	if !platformMatch {
		return stale(
			"target_platform_mismatch",
		)
	}

	// Never trust URL, SHA or release channel stored
	// in the recovery preview.
	// Rehydrate the executable CoreRelease from the
	// currently trusted Core Registry row.
	state.Generation =
		plan.ProposedGeneration

	state.Core =
		model.CoreRelease{
			Type:        target.Type,
			Version:     target.Version,
			DownloadURL: target.DownloadURL,
			SHA256:      target.SHA256,
			Channel:     target.Channel,
		}

	if err :=
		saveDesiredStateTx(
			ctx,
			tx,
			plan.NodeID,
			state,
			target.ID,
		); err != nil {

		return model.RecoveryAttempt{},
			false,
			err
	}

	var deploymentID string

	err =
		tx.QueryRow(
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
		return model.RecoveryAttempt{},
			false,
			err
	}

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE recovery_attempts
			SET
				status = 'executed',
				deployment_id = $2::uuid,
				executed_at = now(),
				failure_reason = NULL,
				updated_at = now()
			WHERE id = $1::uuid
			  AND status = 'approved'
			RETURNING
				deployment_id::text,
				executed_at,
				updated_at
			`,
			plan.ID,
			deploymentID,
		).Scan(
			&plan.DeploymentID,
			&plan.ExecutedAt,
			&plan.UpdatedAt,
		)

	if err != nil {
		return model.RecoveryAttempt{},
			false,
			err
	}

	plan.Status =
		"executed"

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
				'recovery_attempt.executed',
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
					'deployment_id',
						$7::text,
					'core_type',
						$8::text,
					'target_version',
						$9::text,
					'target_channel',
						$10::text,
					'core_release_id',
						$11::text
				)
			)
			`,
			plan.TenantID,
			plan.NodeID,
			plan.ID,
			plan.SourceDeploymentID,
			plan.SourceGeneration,
			plan.ProposedGeneration,
			deploymentID,
			plan.CoreType,
			target.Version,
			target.Channel,
			target.ID,
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
