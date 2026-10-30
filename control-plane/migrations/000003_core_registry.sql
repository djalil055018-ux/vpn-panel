BEGIN;

CREATE TABLE IF NOT EXISTS core_releases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    core_type text NOT NULL,
    version text NOT NULL,

    os text NOT NULL,
    architecture text NOT NULL,

    download_url text NOT NULL,
    sha256 text NOT NULL,

    channel text NOT NULL DEFAULT 'testing',

    upstream_prerelease boolean NOT NULL DEFAULT false,

    approved boolean NOT NULL DEFAULT false,
    approved_at timestamptz,
    approved_by text,

    revoked boolean NOT NULL DEFAULT false,

    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT core_releases_identity_unique
        UNIQUE (
            core_type,
            version,
            os,
            architecture
        ),

    CONSTRAINT core_releases_channel_check
        CHECK (
            channel IN (
                'testing',
                'canary',
                'stable'
            )
        ),

    CONSTRAINT core_releases_sha256_check
        CHECK (
            sha256 ~ '^[0-9a-fA-F]{64}$'
        )
);

CREATE INDEX IF NOT EXISTS
    core_releases_lookup_idx
ON core_releases(
    core_type,
    version,
    os,
    architecture
);

CREATE INDEX IF NOT EXISTS
    core_releases_channel_idx
ON core_releases(
    core_type,
    channel,
    os,
    architecture
)
WHERE approved = true
  AND revoked = false;

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS
        core_release_id uuid
        REFERENCES core_releases(id);

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS
        core_type text;

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS
        updated_at timestamptz
        NOT NULL
        DEFAULT now();

CREATE UNIQUE INDEX IF NOT EXISTS
    deployments_node_generation_unique_idx
ON deployments(node_id, generation);

CREATE INDEX IF NOT EXISTS
    deployments_node_started_idx
ON deployments(node_id, started_at DESC);

CREATE INDEX IF NOT EXISTS
    deployments_status_idx
ON deployments(status);

CREATE INDEX IF NOT EXISTS
    audit_events_node_created_idx
ON audit_events(node_id, created_at DESC);

CREATE INDEX IF NOT EXISTS
    audit_events_tenant_created_idx
ON audit_events(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS
    audit_events_type_created_idx
ON audit_events(event_type, created_at DESC);

COMMIT;
