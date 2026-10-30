package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

var ErrNodeCertificateExists = errors.New(
	"certificate for this domain already exists on node",
)

type nodeCertificateScanner interface {
	Scan(dest ...any) error
}

func scanNodeCertificate(
	row nodeCertificateScanner,
) (
	model.NodeCertificate,
	error,
) {
	var result model.NodeCertificate

	err := row.Scan(
		&result.ID,
		&result.TenantID,
		&result.NodeID,
		&result.Domain,
		&result.Provider,
		&result.ChallengeType,
		&result.Environment,
		&result.ContactEmail,
		&result.Status,
		&result.AutoRenew,
		&result.CertificateRef,
		&result.Issuer,
		&result.FingerprintSHA256,
		&result.NotBefore,
		&result.NotAfter,
		&result.ObservedAt,
		&result.LastError,
		&result.CreatedAt,
		&result.UpdatedAt,
	)

	return result, err
}

func (p *Postgres) CreateNodeCertificate(
	ctx context.Context,
	nodeID string,
	domain string,
	provider string,
	challengeType string,
	environment string,
	contactEmail *string,
	autoRenew bool,
) (
	model.NodeCertificate,
	error,
) {
	row := p.Pool.QueryRow(
		ctx,
		`
		WITH target_node AS (
			SELECT
				id,
				tenant_id
			FROM nodes
			WHERE id = $1::uuid
		),
		new_certificate AS (
			SELECT
				gen_random_uuid() AS id,
				id AS node_id,
				tenant_id
			FROM target_node
		)
		INSERT INTO node_certificates(
			id,
			tenant_id,
			node_id,
			domain,
			provider,
			challenge_type,
			environment,
			contact_email,
			status,
			auto_renew,
			certificate_ref
		)
		SELECT
			nc.id,
			nc.tenant_id,
			nc.node_id,
			$2::text,
			$3::text,
			$4::text,
			$5::text,
			$6::text,
			'draft',
			$7::boolean,
			'certificates/' ||
				nc.id::text
		FROM new_certificate nc
		ON CONFLICT DO NOTHING
		RETURNING
			id::text,
			tenant_id::text,
			node_id::text,
			domain,
			provider,
			challenge_type,
			environment,
			contact_email,
			status,
			auto_renew,
			certificate_ref,
			issuer,
			fingerprint_sha256,
			not_before,
			not_after,
			observed_at,
			last_error,
			created_at,
			updated_at
		`,
		nodeID,
		domain,
		provider,
		challengeType,
		environment,
		contactEmail,
		autoRenew,
	)

	result, err :=
		scanNodeCertificate(row)

	if err == nil {
		return result, nil
	}

	if !errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.NodeCertificate{},
			err
	}

	var nodeExists bool

	err = p.Pool.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM nodes
			WHERE id = $1::uuid
		)
		`,
		nodeID,
	).Scan(
		&nodeExists,
	)

	if err != nil {
		return model.NodeCertificate{},
			err
	}

	if !nodeExists {
		return model.NodeCertificate{},
			ErrNotFound
	}

	return model.NodeCertificate{},
		ErrNodeCertificateExists
}

func (p *Postgres) ListNodeCertificates(
	ctx context.Context,
	nodeID string,
) (
	[]model.NodeCertificate,
	error,
) {
	var exists bool

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM nodes
			WHERE id = $1::uuid
		)
		`,
		nodeID,
	).Scan(
		&exists,
	)

	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, ErrNotFound
	}

	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT
			id::text,
			tenant_id::text,
			node_id::text,
			domain,
			provider,
			challenge_type,
			environment,
			contact_email,
			status,
			auto_renew,
			certificate_ref,
			issuer,
			fingerprint_sha256,
			not_before,
			not_after,
			observed_at,
			last_error,
			created_at,
			updated_at
		FROM node_certificates
		WHERE node_id = $1::uuid
		  AND status <> 'deleted'
		ORDER BY
			created_at ASC,
			id ASC
		`,
		nodeID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	result :=
		make(
			[]model.NodeCertificate,
			0,
		)

	for rows.Next() {
		item, err :=
			scanNodeCertificate(rows)

		if err != nil {
			return nil, err
		}

		result = append(
			result,
			item,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (p *Postgres) GetNodeCertificate(
	ctx context.Context,
	certificateID string,
) (
	model.NodeCertificate,
	error,
) {
	row := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			id::text,
			tenant_id::text,
			node_id::text,
			domain,
			provider,
			challenge_type,
			environment,
			contact_email,
			status,
			auto_renew,
			certificate_ref,
			issuer,
			fingerprint_sha256,
			not_before,
			not_after,
			observed_at,
			last_error,
			created_at,
			updated_at
		FROM node_certificates
		WHERE id = $1::uuid
		`,
		certificateID,
	)

	result, err :=
		scanNodeCertificate(row)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.NodeCertificate{},
			ErrNotFound
	}

	return result, err
}
