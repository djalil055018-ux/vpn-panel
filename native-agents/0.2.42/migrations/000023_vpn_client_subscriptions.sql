BEGIN;

CREATE TABLE IF NOT EXISTS vpn_client_subscriptions (
    id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    client_id UUID NOT NULL
        REFERENCES vpn_clients(id)
        ON DELETE CASCADE,

    token_id BYTEA NOT NULL,

    token_version BIGINT NOT NULL
        DEFAULT 1,

    token_hash BYTEA NOT NULL,

    token_prefix TEXT NOT NULL,

    status TEXT NOT NULL
        DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    rotated_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    last_access_at TIMESTAMPTZ,

    CONSTRAINT vpn_client_subscriptions_token_id_len_chk
        CHECK (octet_length(token_id) = 16),

    CONSTRAINT vpn_client_subscriptions_token_hash_len_chk
        CHECK (octet_length(token_hash) = 32),

    CONSTRAINT vpn_client_subscriptions_version_chk
        CHECK (token_version > 0),

    CONSTRAINT vpn_client_subscriptions_prefix_chk
        CHECK (btrim(token_prefix) <> ''),

    CONSTRAINT vpn_client_subscriptions_status_chk
        CHECK (
            status IN (
                'active',
                'revoked'
            )
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS
vpn_client_subscriptions_token_id_uidx
ON vpn_client_subscriptions(token_id);

CREATE UNIQUE INDEX IF NOT EXISTS
vpn_client_subscriptions_token_hash_uidx
ON vpn_client_subscriptions(token_hash);

CREATE UNIQUE INDEX IF NOT EXISTS
vpn_client_subscriptions_one_active_per_client_uidx
ON vpn_client_subscriptions(client_id)
WHERE status = 'active';

CREATE INDEX IF NOT EXISTS
vpn_client_subscriptions_tenant_idx
ON vpn_client_subscriptions(tenant_id);

CREATE INDEX IF NOT EXISTS
vpn_client_subscriptions_client_idx
ON vpn_client_subscriptions(client_id);

COMMIT;
