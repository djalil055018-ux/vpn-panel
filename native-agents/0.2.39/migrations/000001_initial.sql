CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending',

    bootstrap_token_hash TEXT,
    bootstrap_used_at TIMESTAMPTZ,

    agent_token_hash TEXT,

    agent_version TEXT,

    os_name TEXT,
    os_version TEXT,
    architecture TEXT,

    desired_generation BIGINT NOT NULL DEFAULT 0,
    applied_generation BIGINT NOT NULL DEFAULT 0,

    last_seen_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS nodes_tenant_idx
ON nodes(tenant_id);

CREATE UNIQUE INDEX IF NOT EXISTS nodes_bootstrap_token_hash_idx
ON nodes(bootstrap_token_hash)
WHERE bootstrap_token_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS nodes_agent_token_hash_idx
ON nodes(agent_token_hash)
WHERE agent_token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS desired_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    generation BIGINT NOT NULL,

    document JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE(node_id, generation)
);

CREATE TABLE IF NOT EXISTS node_health (
    node_id UUID PRIMARY KEY
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    healthy BOOLEAN NOT NULL,

    applied_generation BIGINT NOT NULL DEFAULT 0,

    core TEXT,
    core_version TEXT,

    message TEXT,

    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    generation BIGINT NOT NULL,

    status TEXT NOT NULL,

    previous_core_version TEXT,
    requested_core_version TEXT,
    applied_core_version TEXT,

    error_message TEXT,

    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    node_id UUID
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    event_type TEXT NOT NULL,

    actor_type TEXT NOT NULL,
    actor_id TEXT,

    payload JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
