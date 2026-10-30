package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

type VPNServiceReality struct {
	ServiceID string `json:"service_id"`
	TenantID  string `json:"tenant_id"`

	Destination string `json:"destination"`
	ServerName  string `json:"server_name"`
	Fingerprint string `json:"fingerprint"`
	ShortID     string `json:"short_id"`
	SecretRef   string `json:"secret_ref"`

	PublicKey *string `json:"public_key,omitempty"`
}

func (p *Postgres) ConfigureVPNServiceReality(
	ctx context.Context,
	serviceID string,
	destination string,
	serverName string,
	fingerprint string,
	shortID string,
) (
	VPNServiceReality,
	error,
) {
	var result VPNServiceReality

	err :=
		p.Pool.QueryRow(
			ctx,
			`
			INSERT INTO vpn_service_reality(
				service_id,
				tenant_id,
				destination,
				server_name,
				fingerprint,
				short_id,
				secret_ref
			)

			SELECT
				s.id,
				s.tenant_id,
				$2::text,
				$3::text,
				$4::text,
				$5::text,
				'reality/' || s.id::text

			FROM vpn_services s

			WHERE s.id = $1::uuid
			  AND s.protocol = 'vless'
			  AND s.transport = 'tcp'
			  AND s.security = 'reality'
			  AND s.enabled = false

			ON CONFLICT(service_id)
			DO UPDATE SET
				destination =
					EXCLUDED.destination,

				server_name =
					EXCLUDED.server_name,

				fingerprint =
					EXCLUDED.fingerprint,

				short_id =
					EXCLUDED.short_id,

				updated_at =
					now()

			RETURNING
				service_id::text,
				tenant_id::text,
				destination,
				server_name,
				fingerprint,
				short_id,
				secret_ref,
				public_key
			`,
			serviceID,
			destination,
			serverName,
			fingerprint,
			shortID,
		).Scan(
			&result.ServiceID,
			&result.TenantID,
			&result.Destination,
			&result.ServerName,
			&result.Fingerprint,
			&result.ShortID,
			&result.SecretRef,
			&result.PublicKey,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return VPNServiceReality{},
			ErrNotFound
	}

	return result, err
}

func (p *Postgres) UpdateVPNServiceRealityAndRebuild(
	ctx context.Context,
	serviceID string,
	destination string,
	serverName string,
	fingerprint string,
) (
	model.DesiredState,
	error,
) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.DesiredState{}, err
	}
	defer tx.Rollback(ctx)

	var nodeID string

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			s.node_id::text
		FROM vpn_services s
		JOIN vpn_service_reality r
			ON r.service_id = s.id
			AND r.tenant_id = s.tenant_id
		WHERE s.id = $1::uuid
		  AND s.enabled = true
		  AND s.protocol = 'vless'
		  AND s.transport = 'tcp'
		  AND s.security = 'reality'
		FOR UPDATE OF s, r
		`,
		serviceID,
	).Scan(&nodeID)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, ErrNotFound
	}
	if err != nil {
		return model.DesiredState{}, err
	}

	result, err := tx.Exec(
		ctx,
		`
		UPDATE vpn_service_reality
		SET
			destination = $2::text,
			server_name = $3::text,
			fingerprint = $4::text,
			updated_at = now()
		WHERE service_id = $1::uuid
		`,
		serviceID,
		destination,
		serverName,
		fingerprint,
	)
	if err != nil {
		return model.DesiredState{}, err
	}

	if result.RowsAffected() != 1 {
		return model.DesiredState{}, ErrNotFound
	}

	state, coreReleaseID, err :=
		buildNodeDesiredStateTx(
			ctx,
			tx,
			nodeID,
		)
	if err != nil {
		return model.DesiredState{}, err
	}

	if err := saveDesiredStateTx(
		ctx,
		tx,
		nodeID,
		state,
		coreReleaseID,
	); err != nil {
		return model.DesiredState{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.DesiredState{}, err
	}

	return state, nil
}

func (p *Postgres) GetVPNServiceReality(
	ctx context.Context,
	serviceID string,
) (
	VPNServiceReality,
	error,
) {
	var result VPNServiceReality

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			service_id::text,
			tenant_id::text,
			destination,
			server_name,
			fingerprint,
			short_id,
			secret_ref,
			public_key
		FROM vpn_service_reality
		WHERE service_id = $1::uuid
		`,
		serviceID,
	).Scan(
		&result.ServiceID,
		&result.TenantID,
		&result.Destination,
		&result.ServerName,
		&result.Fingerprint,
		&result.ShortID,
		&result.SecretRef,
		&result.PublicKey,
	)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return VPNServiceReality{},
			ErrNotFound
	}

	return result, err
}
