package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"vpn-platform/internal/model"
)

type vpnServiceRowScanner interface {
	Scan(dest ...any) error
}

func scanVPNService(
	row vpnServiceRowScanner,
) (model.VPNService, error) {
	var service model.VPNService

	err := row.Scan(
		&service.ID,
		&service.TenantID,
		&service.NodeID,
		&service.Name,
		&service.Protocol,
		&service.Listen,
		&service.Port,
		&service.Transport,
		&service.Security,
		&service.PublicAddress,
		&service.PublicPort,
		&service.Enabled,
		&service.CreatedAt,
		&service.UpdatedAt,
		&service.SubscriptionName,
	)

	return service, err
}

func (p *Postgres) CreateVPNService(
	ctx context.Context,
	nodeID string,
	name string,
	protocol string,
	listen string,
	port int,
	transport string,
	security string,
	publicAddress *string,
	publicPort *int,
) (model.VPNService, error) {
	row := p.Pool.QueryRow(
		ctx,
		`
		INSERT INTO vpn_services(
			tenant_id,
			node_id,
			name,
			protocol,
			listen,
			port,
			transport,
			security,
			public_address,
			public_port,
			enabled
		)
		SELECT
			n.tenant_id,
			n.id,
			$2::text,
			$3::text,
			$4::text,
			$5::integer,
			$6::text,
			$7::text,
			$8::text,
			$9::integer,
			false
		FROM nodes n
		WHERE n.id = $1::uuid
		RETURNING
			id::text,
			tenant_id::text,
			node_id::text,
			name,
			protocol,
			listen,
			port,
			transport,
			security,
			public_address,
			public_port,
			enabled,
			created_at,
			updated_at,
			subscription_name
		`,
		nodeID,
		name,
		protocol,
		listen,
		port,
		transport,
		security,
		publicAddress,
		publicPort,
	)

	service, err := scanVPNService(row)
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "23514" && (databaseError.Message == "service runtime differs from node selection" || databaseError.Message == "Hysteria requires UDP and TLS") {
		return model.VPNService{}, ErrNodeRuntime
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNService{}, ErrNotFound
	}

	return service, err
}

func (p *Postgres) ListVPNServices(
	ctx context.Context,
	nodeID string,
) ([]model.VPNService, error) {
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
	).Scan(&exists)

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
			name,
			protocol,
			listen,
			port,
			transport,
			security,
			public_address,
			public_port,
			enabled,
			created_at,
			updated_at,
			subscription_name
		FROM vpn_services
		WHERE node_id = $1::uuid
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

	services := make(
		[]model.VPNService,
		0,
	)

	for rows.Next() {
		service, err :=
			scanVPNService(rows)

		if err != nil {
			return nil, err
		}

		services = append(
			services,
			service,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := p.decorateVPNServiceNames(ctx, services); err != nil {
		return nil, err
	}
	return services, nil
}

func (p *Postgres) GetVPNService(
	ctx context.Context,
	serviceID string,
) (model.VPNService, error) {
	row := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			id::text,
			tenant_id::text,
			node_id::text,
			name,
			protocol,
			listen,
			port,
			transport,
			security,
			public_address,
			public_port,
			enabled,
			created_at,
			updated_at,
			subscription_name
		FROM vpn_services
		WHERE id = $1::uuid
		`,
		serviceID,
	)

	service, err := scanVPNService(row)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNService{}, ErrNotFound
	}

	if err != nil {
		return service, err
	}
	services := []model.VPNService{service}
	if err = p.decorateVPNServiceNames(ctx, services); err != nil {
		return model.VPNService{}, err
	}
	return services[0], nil
}

func (p *Postgres) AttachVPNClientToService(
	ctx context.Context,
	serviceID string,
	clientID string,
) (model.VPNClientService, error) {
	var result model.VPNClientService

	err := p.Pool.QueryRow(
		ctx,
		`
		INSERT INTO vpn_client_services(
			tenant_id,
			client_id,
			service_id
		)
		SELECT
			s.tenant_id,
			c.id,
			s.id
		FROM vpn_services s
		JOIN vpn_clients c
			ON c.id = $2::uuid
			AND c.tenant_id = s.tenant_id
		WHERE s.id = $1::uuid

		ON CONFLICT (
			client_id,
			service_id
		)
		DO UPDATE
		SET tenant_id = EXCLUDED.tenant_id

		RETURNING
			tenant_id::text,
			client_id::text,
			service_id::text,
			created_at
		`,
		serviceID,
		clientID,
	).Scan(
		&result.TenantID,
		&result.ClientID,
		&result.ServiceID,
		&result.CreatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNClientService{}, ErrNotFound
	}

	return result, err
}

func (p *Postgres) DetachVPNClientFromService(
	ctx context.Context,
	serviceID string,
	clientID string,
) error {
	tag, err := p.Pool.Exec(
		ctx,
		`
		DELETE FROM vpn_client_services
		WHERE service_id = $1::uuid
		  AND client_id = $2::uuid
		`,
		serviceID,
		clientID,
	)

	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

func (p *Postgres) UpdateVPNServiceSettings(
	ctx context.Context,
	serviceID string,
	name string,
	publicAddress string,
	publicPort int,
) (model.VPNService, error) {
	row := p.Pool.QueryRow(
		ctx,
		`
		UPDATE vpn_services
		SET
			name = CASE WHEN $2::text = '' THEN name ELSE $2::text END,
			public_address = $3::text,
			public_port = $4::integer,
			updated_at = now()
		WHERE id = $1::uuid
		RETURNING
			id::text,
			tenant_id::text,
			node_id::text,
			name,
			protocol,
			listen,
			port,
			transport,
			security,
			public_address,
			public_port,
			enabled,
			created_at,
			updated_at,
			subscription_name
		`,
		serviceID,
		name,
		publicAddress,
		publicPort,
	)

	service, err := scanVPNService(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNService{}, ErrNotFound
	}

	return service, err
}

func (p *Postgres) ListVPNClientDirectServiceIDs(
	ctx context.Context,
	clientID string,
) ([]string, error) {
	if _, err := p.GetVPNClient(ctx, clientID); err != nil {
		return nil, err
	}

	rows, err := p.Pool.Query(
		ctx,
		`
		SELECT service_id::text
		FROM vpn_client_services
		WHERE client_id = $1::uuid
		ORDER BY created_at ASC, service_id ASC
		`,
		clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]string, 0)

	for rows.Next() {
		var serviceID string
		if err := rows.Scan(&serviceID); err != nil {
			return nil, err
		}
		result = append(result, serviceID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
