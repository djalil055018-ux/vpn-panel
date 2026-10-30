BEGIN;

CREATE TABLE IF NOT EXISTS vpn_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,

    vless_uuid UUID NOT NULL
        DEFAULT gen_random_uuid(),

    status TEXT NOT NULL
        DEFAULT 'active',

    expires_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT vpn_clients_name_not_empty_chk
        CHECK (btrim(name) <> ''),

    CONSTRAINT vpn_clients_status_chk
        CHECK (
            status IN (
                'active',
                'disabled'
            )
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS
vpn_clients_vless_uuid_uidx
ON vpn_clients(vless_uuid);

CREATE INDEX IF NOT EXISTS
vpn_clients_tenant_idx
ON vpn_clients(tenant_id);

CREATE INDEX IF NOT EXISTS
vpn_clients_expiry_idx
ON vpn_clients(expires_at)
WHERE expires_at IS NOT NULL;

COMMIT;
