package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

const xrayBootstrapVersion = "26.9.9"

// InitializeXrayRuntime creates the immutable generation-1 baseline
// for a freshly registered Xray node.
//
// The initializer is intentionally idempotent:
//   - it never replaces an existing desired generation;
//   - it requires an already registered Xray node;
//   - it refuses initialization while any service is enabled;
//   - imported nodes retain their generation for the adoption workflow;
//   - it accepts only an approved, non-revoked reviewed Xray release
//     compatible with the node OS and architecture.
func (p *Postgres) InitializeXrayRuntime(
	ctx context.Context,
	nodeID string,
) (
	model.DesiredState,
	bool,
	error,
) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.DesiredState{}, false, err
	}

	defer tx.Rollback(context.WithoutCancel(ctx))

	var runtime string
	var generation int64
	var registered bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			runtime_core,
			desired_generation,
			agent_token_hash IS NOT NULL
		FROM nodes
		WHERE id = $1::uuid
		FOR UPDATE
		`,
		nodeID,
	).Scan(
		&runtime,
		&generation,
		&registered,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, false, ErrNotFound
	}

	if err != nil {
		return model.DesiredState{}, false, err
	}

	if runtime != "xray" || !registered {
		return model.DesiredState{}, false, ErrNodeRuntime
	}

	// Preparation and initialization both lock the node. Checking the registry
	// under that lock prevents an ordinary bootstrap from consuming generation 1
	// after an imported profile has been prepared. The adoption transaction must
	// publish the source profile and authorized membership together.
	var imported bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM node_xray_profiles WHERE node_id=$1::uuid
	)`, nodeID).Scan(&imported)
	if err != nil {
		return model.DesiredState{}, false, err
	}
	if imported {
		return model.DesiredState{}, false, ErrXrayProfileHeld
	}

	// Idempotent retry: an initialized node returns its current
	// generation and does not create another deployment.
	if generation > 0 {
		var raw []byte
		var state model.DesiredState

		err = tx.QueryRow(
			ctx,
			`
			SELECT document
			FROM desired_states
			WHERE node_id = $1::uuid
			  AND generation = $2
			`,
			nodeID,
			generation,
		).Scan(&raw)

		if err != nil {
			return state, false, err
		}

		if err = json.Unmarshal(raw, &state); err != nil {
			return state, false, err
		}

		return state, false, tx.Commit(ctx)
	}

	var enabled bool

	err = tx.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM vpn_services
			WHERE node_id = $1::uuid
			  AND enabled
		)
		`,
		nodeID,
	).Scan(&enabled)

	if err != nil {
		return model.DesiredState{}, false, err
	}

	if enabled {
		return model.DesiredState{},
			false,
			errors.New(
				"initial runtime requires all services to be disabled",
			)
	}

	var releaseID string
	var release model.CoreRelease

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			cr.id::text,
			cr.core_type,
			cr.version,
			cr.download_url,
			cr.sha256,
			cr.channel
		FROM core_releases cr
		JOIN nodes n
		  ON n.id = $1::uuid
		WHERE cr.core_type = 'xray'
		  AND cr.version = $2
		  AND cr.architecture =
		      COALESCE(n.architecture, '')
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
		FOR SHARE OF cr
		`,
		nodeID,
		xrayBootstrapVersion,
	).Scan(
		&releaseID,
		&release.Type,
		&release.Version,
		&release.DownloadURL,
		&release.SHA256,
		&release.Channel,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{},
			false,
			ErrPinnedCoreReleaseUnavailable
	}

	if err != nil {
		return model.DesiredState{}, false, err
	}

	state := model.DesiredState{
		Generation: 1,
		Core:       release,
		Services:   []model.ServiceSpec{},
	}

	if err = saveDesiredStateTx(
		ctx,
		tx,
		nodeID,
		state,
		releaseID,
	); err != nil {
		return model.DesiredState{}, false, err
	}

	if err = tx.Commit(ctx); err != nil {
		return model.DesiredState{}, false, err
	}

	return state, true, nil
}
