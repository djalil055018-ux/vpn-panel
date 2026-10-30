package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

func (p *Postgres) RotateNodeBootstrapToken(
	ctx context.Context,
	nodeID string,
	bootstrapHash string,
) (model.Node, error) {
	tx, err :=
		p.Pool.Begin(ctx)
	if err != nil {
		return model.Node{}, err
	}

	defer tx.Rollback(ctx)

	var tenantID string
	var registered bool
	var retired bool

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				tenant_id::text,
				(agent_token_hash IS NOT NULL),status='retired'
			FROM nodes
			WHERE id = $1::uuid
			FOR UPDATE
			`,
			nodeID,
		).Scan(
			&tenantID,
			&registered, &retired,
		)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.Node{}, ErrNotFound
	}

	if err != nil {
		return model.Node{}, err
	}

	if retired {
		return model.Node{}, ErrNodeRetired
	}
	if registered {
		return model.Node{},
			ErrNodeAlreadyRegistered
	}

	var node model.Node

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE nodes
			SET
				bootstrap_token_hash = $2,
				bootstrap_used_at = NULL,
				status = 'pending'
			WHERE id = $1::uuid
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
			nodeID,
			bootstrapHash,
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

	if err != nil {
		return model.Node{}, err
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
				'node.bootstrap.rotated',
				'admin',
				'control-plane',
				jsonb_build_object(
					'node_id',
					$2::text
				)
			)
			`,
			tenantID,
			nodeID,
		)

	if err != nil {
		return model.Node{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.Node{}, err
	}

	return node, nil
}
