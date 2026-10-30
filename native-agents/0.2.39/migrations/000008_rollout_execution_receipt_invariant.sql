DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'rollout_plans_executed_requires_deployment_chk'
    ) THEN
        ALTER TABLE rollout_plans
        ADD CONSTRAINT
            rollout_plans_executed_requires_deployment_chk
        CHECK (
            status <> 'executed'
            OR deployment_id IS NOT NULL
        )
        NOT VALID;
    END IF;
END
$$;

ALTER TABLE rollout_plans
VALIDATE CONSTRAINT
    rollout_plans_executed_requires_deployment_chk;
