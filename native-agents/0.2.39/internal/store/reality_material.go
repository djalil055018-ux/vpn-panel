package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

var ErrRealityPublicKeyConflict = errors.New("reality public key conflict")

func (p *Postgres) SaveRealityPublicMaterial(
	ctx context.Context,
	nodeID string,
	material model.RealityPublicMaterial,
) error {
	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	var currentPublicKey string

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				COALESCE(
					r.public_key,
					''
				)
			FROM vpn_service_reality r
			JOIN vpn_services s
				ON s.id = r.service_id
				AND s.tenant_id = r.tenant_id
			WHERE r.service_id = $1::uuid
			  AND s.node_id = $2::uuid
			  AND s.security = 'reality'
			FOR UPDATE OF r
			`,
			material.ServiceID,
			nodeID,
		).Scan(
			&currentPublicKey,
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

	if currentPublicKey != "" &&
		currentPublicKey != material.PublicKey {

		return ErrRealityPublicKeyConflict
	}

	_, err =
		tx.Exec(
			ctx,
			`
			UPDATE vpn_service_reality
			SET
				public_key = $2::text,
				public_key_observed_at = now(),
				updated_at = now()
			WHERE service_id = $1::uuid
			`,
			material.ServiceID,
			material.PublicKey,
		)

	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
