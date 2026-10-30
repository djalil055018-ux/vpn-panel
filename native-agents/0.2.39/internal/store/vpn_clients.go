package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

type vpnClientRowScanner interface {
	Scan(dest ...any) error
}

func scanVPNClient(
	row vpnClientRowScanner,
) (model.VPNClient, error) {
	var client model.VPNClient

	err := row.Scan(
		&client.ID,
		&client.TenantID,
		&client.Name,
		&client.VLESSUUID,
		&client.Status,
		&client.EffectiveStatus,
		&client.ExpiresAt,
		&client.CreatedAt,
		&client.UpdatedAt,
		&client.RemnawaveHold,
	)

	return client, err
}

func (p *Postgres) CreateVPNClient(
	ctx context.Context,
	tenantID string,
	name string,
	expiresAt *time.Time,
) (model.VPNClient, error) {
	if !tenantScopeAllowed(ctx, tenantID) {
		return model.VPNClient{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.VPNClient{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = checkTenantQuota(ctx, tx, tenantID, "client"); err != nil {
		return model.VPNClient{}, err
	}
	row := tx.QueryRow(
		ctx,
		`
		INSERT INTO vpn_clients(
			tenant_id,
			name,
			expires_at
		)
		SELECT
			$1::uuid,
			$2::text,
			$3::timestamptz
		WHERE EXISTS (
			SELECT 1
			FROM tenants
			WHERE id = $1::uuid
		)
		RETURNING
			id::text,
			tenant_id::text,
			name,
			vless_uuid::text,
			status,
			CASE
				WHEN status = 'disabled'
					THEN 'disabled'
				WHEN expires_at IS NOT NULL
					AND expires_at <= now()
					THEN 'expired'
				WHEN vpn_client_quota_exceeded(vpn_clients.id)
					THEN 'quota_exceeded'
				ELSE 'active'
			END,
			expires_at,
			created_at,
			updated_at,
			remnawave_hold
		`,
		tenantID,
		name,
		expiresAt,
	)

	client, err := scanVPNClient(row)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNClient{}, ErrNotFound
	}

	if err != nil {
		return client, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.created',$2,$3,jsonb_build_object('client_id',$4::text))`, tenantID, actorType, actorID, client.ID)
	if err != nil {
		return client, err
	}
	return client, tx.Commit(ctx)
}

func (p *Postgres) ListVPNClients(
	ctx context.Context,
	tenantID string,
) ([]model.VPNClient, error) {
	if !tenantScopeAllowed(ctx, tenantID) {
		return nil, ErrNotFound
	}
	var exists bool

	err := p.Pool.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM tenants
			WHERE id = $1::uuid
		)
		`,
		tenantID,
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
			name,
			vless_uuid::text,
			status,
			CASE
				WHEN status = 'disabled'
					THEN 'disabled'
				WHEN expires_at IS NOT NULL
					AND expires_at <= now()
					THEN 'expired'
				WHEN vpn_client_quota_exceeded(vpn_clients.id)
					THEN 'quota_exceeded'
				ELSE 'active'
			END,
			expires_at,
			created_at,
			updated_at,
			remnawave_hold
		FROM vpn_clients
		WHERE tenant_id = $1::uuid
		ORDER BY
			created_at DESC,
			id DESC
		`,
		tenantID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	clients := make(
		[]model.VPNClient,
		0,
	)

	for rows.Next() {
		client, err := scanVPNClient(rows)
		if err != nil {
			return nil, err
		}

		clients = append(
			clients,
			client,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows.Close()
	if err := p.enrichClientDirectory(ctx, tenantID, clients); err != nil {
		return nil, err
	}
	return clients, nil
}

func (p *Postgres) GetVPNClient(
	ctx context.Context,
	clientID string,
) (model.VPNClient, error) {
	row := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			id::text,
			tenant_id::text,
			name,
			vless_uuid::text,
			status,
			CASE
				WHEN status = 'disabled'
					THEN 'disabled'
				WHEN expires_at IS NOT NULL
					AND expires_at <= now()
					THEN 'expired'
				WHEN vpn_client_quota_exceeded(vpn_clients.id)
					THEN 'quota_exceeded'
				ELSE 'active'
			END,
			expires_at,
			created_at,
			updated_at,
			remnawave_hold
		FROM vpn_clients
		WHERE id = $1::uuid
		`,
		clientID,
	)

	client, err := scanVPNClient(row)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNClient{}, ErrNotFound
	}
	if err == nil && !tenantScopeAllowed(ctx, client.TenantID) {
		return model.VPNClient{}, ErrNotFound
	}

	return client, err
}

func (p *Postgres) UpdateVPNClient(ctx context.Context, clientID string, name, status *string, expiresAt *time.Time, setExpiresAt bool) (model.VPNClient, error) {
	return p.mutateVPNClient(ctx, clientID, name, status, expiresAt, setExpiresAt)
}
func (p *Postgres) SetVPNClientStatus(
	ctx context.Context,
	clientID string,
	status string,
) (model.VPNClient, error) {
	return p.UpdateVPNClient(
		ctx,
		clientID,
		nil,
		&status,
		nil,
		false,
	)
}
