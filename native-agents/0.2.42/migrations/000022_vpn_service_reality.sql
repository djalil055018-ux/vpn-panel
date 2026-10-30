BEGIN;

CREATE TABLE vpn_service_reality (
    service_id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL,

    destination TEXT NOT NULL,

    server_name TEXT NOT NULL,

    fingerprint TEXT NOT NULL
        DEFAULT 'chrome',

    short_id TEXT NOT NULL,

    secret_ref TEXT NOT NULL,

    public_key TEXT,

    public_key_observed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT vpn_service_reality_service_tenant_fk
        FOREIGN KEY (
            service_id,
            tenant_id
        )
        REFERENCES vpn_services(
            id,
            tenant_id
        )
        ON DELETE CASCADE,

    CONSTRAINT vpn_service_reality_destination_chk
        CHECK (btrim(destination) <> ''),

    CONSTRAINT vpn_service_reality_server_name_chk
        CHECK (btrim(server_name) <> ''),

    CONSTRAINT vpn_service_reality_fingerprint_chk
        CHECK (btrim(fingerprint) <> ''),

    CONSTRAINT vpn_service_reality_short_id_chk
        CHECK (
            short_id ~ '^[0-9a-f]{16}$'
        ),

    CONSTRAINT vpn_service_reality_secret_ref_chk
        CHECK (
            secret_ref ~ '^reality/[0-9a-f-]{36}$'
        ),

    CONSTRAINT vpn_service_reality_public_key_chk
        CHECK (
            public_key IS NULL
            OR btrim(public_key) <> ''
        ),

    CONSTRAINT vpn_service_reality_secret_ref_unique
        UNIQUE (secret_ref)
);

CREATE INDEX vpn_service_reality_tenant_idx
ON vpn_service_reality(tenant_id);

COMMIT;
