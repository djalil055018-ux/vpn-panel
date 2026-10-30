ALTER TABLE rollout_plans
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

UPDATE rollout_plans
SET expires_at =
    created_at + INTERVAL '1 hour'
WHERE expires_at IS NULL;

ALTER TABLE rollout_plans
ALTER COLUMN expires_at
SET DEFAULT (now() + INTERVAL '1 hour');

ALTER TABLE rollout_plans
ALTER COLUMN expires_at
SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'rollout_plans_expires_after_created_chk'
    ) THEN
        ALTER TABLE rollout_plans
        ADD CONSTRAINT
            rollout_plans_expires_after_created_chk
        CHECK (
            expires_at > created_at
        );
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS
    rollout_plans_one_active_per_node_idx
ON rollout_plans(node_id)
WHERE status IN (
    'planned',
    'approved'
);

CREATE INDEX IF NOT EXISTS
    rollout_plans_active_expiry_idx
ON rollout_plans(expires_at)
WHERE status IN (
    'planned',
    'approved'
);
