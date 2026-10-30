package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrVPNClientSubscriptionExists = errors.New("active vpn client subscription already exists")

var ErrVPNClientSubscriptionConflict = errors.New("vpn client subscription changed concurrently")

type VPNClientSubscription struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	ClientID     string     `json:"client_id"`
	TokenVersion int64      `json:"token_version"`
	TokenPrefix  string     `json:"token_prefix"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	RotatedAt    *time.Time `json:"rotated_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	LastAccessAt *time.Time `json:"last_access_at,omitempty"`
	TokenID      []byte     `json:"-"`
	TokenHash    []byte     `json:"-"`
}

type vpnClientSubscriptionScanner interface {
	Scan(dest ...any) error
}

func scanVPNClientSubscription(
	row vpnClientSubscriptionScanner,
) (VPNClientSubscription, error) {
	var result VPNClientSubscription

	err := row.Scan(
		&result.ID,
		&result.TenantID,
		&result.ClientID,
		&result.TokenID,
		&result.TokenVersion,
		&result.TokenHash,
		&result.TokenPrefix,
		&result.Status,
		&result.CreatedAt,
		&result.RotatedAt,
		&result.RevokedAt,
		&result.LastAccessAt,
	)

	return result, err
}

func (p *Postgres) CreateVPNClientSubscription(
	ctx context.Context,
	clientID string,
	tokenID []byte,
	tokenVersion int64,
	tokenHash []byte,
	tokenPrefix string,
) (VPNClientSubscription, error) {
	if principal, ok := TenantPrincipal(ctx); ok {
		owns, err := p.TenantOwnsResource(ctx, principal.TenantID, "client", clientID)
		if err != nil {
			return VPNClientSubscription{}, err
		}
		if !owns {
			return VPNClientSubscription{}, ErrNotFound
		}
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return VPNClientSubscription{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	row := tx.QueryRow(
		ctx,
		`
		INSERT INTO vpn_client_subscriptions(
			tenant_id,
			client_id,
			token_id,
			token_version,
			token_hash,
			token_prefix,
			status
		)
		SELECT
			c.tenant_id,
			c.id,
			$2::bytea,
			$3::bigint,
			$4::bytea,
			$5::text,
			'active'
		FROM vpn_clients c
		WHERE c.id = $1::uuid
		  AND c.status = 'active'
		  AND (
			c.expires_at IS NULL
			OR c.expires_at > now()
		  )
		  AND NOT vpn_client_quota_exceeded(c.id)
		ON CONFLICT DO NOTHING
		RETURNING
			id::text,
			tenant_id::text,
			client_id::text,
			token_id,
			token_version,
			token_hash,
			token_prefix,
			status,
			created_at,
			rotated_at,
			revoked_at,
			last_access_at
		`,
		clientID,
		tokenID,
		tokenVersion,
		tokenHash,
		tokenPrefix,
	)

	result, err := scanVPNClientSubscription(row)

	if err == nil {
		actorType, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_subscription.created',$2,$3,jsonb_build_object('client_id',$4::text))`, result.TenantID, actorType, actorID, clientID)
		if err != nil {
			return result, err
		}
		return result, tx.Commit(ctx)
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return VPNClientSubscription{}, err
	}

	var clientUsable bool

	err = p.Pool.QueryRow(
		ctx,
		`
		SELECT EXISTS(
			SELECT 1
			FROM vpn_clients
			WHERE id = $1::uuid
			  AND status = 'active'
			  AND (
				expires_at IS NULL
				OR expires_at > now()
			  )
			  AND NOT vpn_client_quota_exceeded(vpn_clients.id)
		)
		`,
		clientID,
	).Scan(&clientUsable)

	if err != nil {
		return VPNClientSubscription{}, err
	}

	if !clientUsable {
		return VPNClientSubscription{}, ErrNotFound
	}

	return VPNClientSubscription{},
		ErrVPNClientSubscriptionExists
}

func (p *Postgres) GetVPNClientSubscription(
	ctx context.Context,
	clientID string,
) (VPNClientSubscription, error) {
	row := p.Pool.QueryRow(
		ctx,
		`
		SELECT
			s.id::text,
			s.tenant_id::text,
			s.client_id::text,
			s.token_id,
			s.token_version,
			s.token_hash,
			s.token_prefix,
			s.status,
			s.created_at,
			s.rotated_at,
			s.revoked_at,
			s.last_access_at
		FROM vpn_client_subscriptions s
		WHERE s.client_id = $1::uuid
		  AND s.status = 'active'
		`,
		clientID,
	)

	result, err := scanVPNClientSubscription(row)

	if errors.Is(err, pgx.ErrNoRows) {
		return VPNClientSubscription{}, ErrNotFound
	}
	if err == nil && !tenantScopeAllowed(ctx, result.TenantID) {
		return VPNClientSubscription{}, ErrNotFound
	}

	return result, err
}

func (p *Postgres) RotateVPNClientSubscription(
	ctx context.Context,
	clientID string,
	oldVersion int64,
	newVersion int64,
	tokenHash []byte,
	tokenPrefix string,
) (VPNClientSubscription, error) {
	if principal, ok := TenantPrincipal(ctx); ok {
		owns, err := p.TenantOwnsResource(ctx, principal.TenantID, "client", clientID)
		if err != nil {
			return VPNClientSubscription{}, err
		}
		if !owns {
			return VPNClientSubscription{}, ErrNotFound
		}
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return VPNClientSubscription{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	row := tx.QueryRow(
		ctx,
		`
		UPDATE vpn_client_subscriptions
		SET
			token_version = $3::bigint,
			token_hash = $4::bytea,
			token_prefix = $5::text,
			rotated_at = now()
		WHERE client_id = $1::uuid
		  AND status = 'active'
		  AND token_version = $2::bigint
		RETURNING
			id::text,
			tenant_id::text,
			client_id::text,
			token_id,
			token_version,
			token_hash,
			token_prefix,
			status,
			created_at,
			rotated_at,
			revoked_at,
			last_access_at
		`,
		clientID,
		oldVersion,
		newVersion,
		tokenHash,
		tokenPrefix,
	)

	result, err := scanVPNClientSubscription(row)

	if errors.Is(err, pgx.ErrNoRows) {
		return VPNClientSubscription{},
			ErrVPNClientSubscriptionConflict
	}

	if err != nil {
		return result, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_subscription.rotated',$2,$3,jsonb_build_object('client_id',$4::text))`, result.TenantID, actorType, actorID, clientID)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (p *Postgres) ResolveVPNClientSubscription(
	ctx context.Context,
	tokenID []byte,
	tokenVersion int64,
	tokenHash []byte,
) (string, error) {
	var clientID string

	err := p.Pool.QueryRow(
		ctx,
		`
		UPDATE vpn_client_subscriptions s
		SET
			last_access_at = now()
		FROM vpn_clients c
		WHERE s.token_id = $1::bytea
		  AND s.token_version = $2::bigint
		  AND s.token_hash = $3::bytea
		  AND s.status = 'active'
		  AND c.id = s.client_id
		  AND c.tenant_id = s.tenant_id
		  AND c.status = 'active'
		  AND (
			c.expires_at IS NULL
			OR c.expires_at > now()
		  )
		  AND NOT vpn_client_quota_exceeded(c.id)
		RETURNING
			s.client_id::text
		`,
		tokenID,
		tokenVersion,
		tokenHash,
	).Scan(&clientID)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}

	return clientID, err
}
