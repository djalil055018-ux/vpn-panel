CREATE TABLE IF NOT EXISTS node_core_update_policies (
    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    core_type TEXT NOT NULL,

    policy TEXT NOT NULL DEFAULT 'pinned'
        CHECK (
            policy IN (
                'pinned',
                'testing',
                'canary',
                'stable'
            )
        ),

    pinned_version TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY(node_id, core_type),

    CHECK (
        (
            policy = 'pinned'
            AND pinned_version IS NOT NULL
            AND btrim(pinned_version) <> ''
        )
        OR
        (
            policy <> 'pinned'
            AND pinned_version IS NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS
    node_core_update_policies_policy_idx
ON node_core_update_policies(
    core_type,
    policy
);

INSERT INTO node_core_update_policies(
    node_id,
    core_type,
    policy,
    pinned_version
)
SELECT
    nh.node_id,
    nh.core,
    'pinned',
    nh.core_version
FROM node_health nh
WHERE NULLIF(btrim(nh.core), '') IS NOT NULL
  AND NULLIF(btrim(nh.core_version), '') IS NOT NULL
ON CONFLICT(node_id, core_type) DO NOTHING;
