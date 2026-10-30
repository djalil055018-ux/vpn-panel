BEGIN;

CREATE TABLE IF NOT EXISTS certificate_jobs (
    id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    certificate_id UUID NOT NULL
        REFERENCES node_certificates(id)
        ON DELETE CASCADE,

    operation TEXT NOT NULL,

    status TEXT NOT NULL
        DEFAULT 'pending',

    owner_instance_id UUID,

    lease_token_hash TEXT,

    lease_expires_at TIMESTAMPTZ,

    attempt INTEGER NOT NULL
        DEFAULT 0,

    last_error TEXT,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    claimed_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT certificate_jobs_operation_chk
        CHECK (
            operation IN (
                'issue',
                'renew'
            )
        ),

    CONSTRAINT certificate_jobs_status_chk
        CHECK (
            status IN (
                'pending',
                'claimed',
                'completed',
                'failed'
            )
        ),

    CONSTRAINT certificate_jobs_attempt_chk
        CHECK (attempt >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS
certificate_jobs_one_active_per_certificate_uidx
ON certificate_jobs(certificate_id)
WHERE status IN (
    'pending',
    'claimed'
);

CREATE INDEX IF NOT EXISTS
certificate_jobs_node_status_idx
ON certificate_jobs(
    node_id,
    status,
    created_at
);

CREATE INDEX IF NOT EXISTS
certificate_jobs_certificate_idx
ON certificate_jobs(certificate_id);

CREATE INDEX IF NOT EXISTS
certificate_jobs_lease_idx
ON certificate_jobs(lease_expires_at)
WHERE status = 'claimed';

COMMIT;
