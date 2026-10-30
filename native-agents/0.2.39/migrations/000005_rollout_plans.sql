CREATE TABLE IF NOT EXISTS rollout_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    core_type TEXT NOT NULL,

    policy TEXT NOT NULL
        CHECK (
            policy IN (
                'pinned',
                'testing',
                'canary',
                'stable'
            )
        ),

    pinned_version TEXT,

    base_generation BIGINT NOT NULL,
    proposed_generation BIGINT NOT NULL,

    from_version TEXT,

    target_core_release_id UUID
        REFERENCES core_releases(id),

    target_version TEXT,
    target_channel TEXT,

    status TEXT NOT NULL
        CHECK (
            status IN (
                'blocked',
                'planned',
                'approved',
                'executed',
                'cancelled',
                'failed',
                'stale'
            )
        ),

    blockers JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (
            jsonb_typeof(blockers) = 'array'
        ),

    desired_state_preview JSONB,

    created_by TEXT NOT NULL DEFAULT 'control-plane',

    approved_by TEXT,
    approved_at TIMESTAMPTZ,

    executed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,

    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (
        proposed_generation > base_generation
    )
);

CREATE INDEX IF NOT EXISTS rollout_plans_node_created_idx
ON rollout_plans(
    node_id,
    created_at DESC
);

CREATE INDEX IF NOT EXISTS rollout_plans_status_idx
ON rollout_plans(status);

CREATE INDEX IF NOT EXISTS rollout_plans_target_release_idx
ON rollout_plans(target_core_release_id)
WHERE target_core_release_id IS NOT NULL;
