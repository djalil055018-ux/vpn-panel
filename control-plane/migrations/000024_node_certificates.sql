BEGIN;

CREATE TABLE IF NOT EXISTS node_certificates (
    id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    domain TEXT NOT NULL,

    provider TEXT NOT NULL
        DEFAULT 'letsencrypt',

    challenge_type TEXT NOT NULL
        DEFAULT 'http-01',

    environment TEXT NOT NULL
        DEFAULT 'staging',

    contact_email TEXT,

    status TEXT NOT NULL
        DEFAULT 'draft',

    auto_renew BOOLEAN NOT NULL
        DEFAULT true,

    certificate_ref TEXT NOT NULL,

    issuer TEXT,

    fingerprint_sha256 TEXT,

    not_before TIMESTAMPTZ,

    not_after TIMESTAMPTZ,

    observed_at TIMESTAMPTZ,

    last_error TEXT,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT node_certificates_domain_chk
        CHECK (btrim(domain) <> ''),

    CONSTRAINT node_certificates_provider_chk
        CHECK (
            provider IN (
                'letsencrypt'
            )
        ),

    CONSTRAINT node_certificates_challenge_chk
        CHECK (
            challenge_type IN (
                'http-01'
            )
        ),

    CONSTRAINT node_certificates_environment_chk
        CHECK (
            environment IN (
                'staging',
                'production'
            )
        ),

    CONSTRAINT node_certificates_status_chk
        CHECK (
            status IN (
                'draft',
                'pending',
                'issuing',
                'active',
                'renewing',
                'failed',
                'revoked'
            )
        ),

    CONSTRAINT node_certificates_ref_chk
        CHECK (
            certificate_ref ~
            '^certificates/[0-9a-f-]{36}$'
        ),

    CONSTRAINT node_certificates_ref_unique
        UNIQUE (certificate_ref)
);

CREATE UNIQUE INDEX IF NOT EXISTS
node_certificates_node_domain_active_uidx
ON node_certificates(
    node_id,
    domain
)
WHERE status <> 'revoked';

CREATE INDEX IF NOT EXISTS
node_certificates_node_idx
ON node_certificates(node_id);

CREATE INDEX IF NOT EXISTS
node_certificates_tenant_idx
ON node_certificates(tenant_id);

CREATE INDEX IF NOT EXISTS
node_certificates_status_idx
ON node_certificates(status);

CREATE INDEX IF NOT EXISTS
node_certificates_expiry_idx
ON node_certificates(not_after)
WHERE not_after IS NOT NULL;

COMMIT;
