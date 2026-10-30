ALTER TABLE rollout_plans
ADD COLUMN IF NOT EXISTS outcome_status TEXT;

ALTER TABLE rollout_plans
ADD COLUMN IF NOT EXISTS outcome_at TIMESTAMPTZ;

ALTER TABLE rollout_plans
ADD COLUMN IF NOT EXISTS outcome_reason TEXT;

UPDATE rollout_plans rp
SET
    outcome_status = d.status,

    outcome_at =
        CASE
            WHEN d.status IN (
                'healthy',
                'failed',
                'rolled_back'
            )
            THEN COALESCE(
                d.completed_at,
                d.updated_at
            )
            ELSE NULL
        END,

    outcome_reason =
        CASE
            WHEN d.status IN (
                'failed',
                'rolled_back'
            )
            THEN d.error_message
            ELSE NULL
        END

FROM deployments d

WHERE rp.deployment_id = d.id
  AND rp.status = 'executed'
  AND rp.outcome_status IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'rollout_plans_outcome_status_chk'
    ) THEN
        ALTER TABLE rollout_plans
        ADD CONSTRAINT
            rollout_plans_outcome_status_chk
        CHECK (
            outcome_status IS NULL
            OR outcome_status IN (
                'pending',
                'applying',
                'healthy',
                'failed',
                'rolled_back'
            )
        );
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS
    rollout_plans_outcome_status_idx
ON rollout_plans(outcome_status)
WHERE status = 'executed';
