CREATE OR REPLACE FUNCTION
vpn_platform_status_transition_allowed(
    old_status TEXT,
    new_status TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    IF old_status IS NOT DISTINCT FROM new_status THEN
        RETURN TRUE;
    END IF;

    IF old_status IS NULL THEN
        RETURN new_status IN (
            'pending',
            'applying',
            'healthy',
            'failed',
            'rolled_back'
        );
    END IF;

    IF old_status = 'pending' THEN
        RETURN new_status IN (
            'applying',
            'healthy',
            'failed',
            'rolled_back'
        );
    END IF;

    IF old_status = 'applying' THEN
        RETURN new_status IN (
            'healthy',
            'failed',
            'rolled_back'
        );
    END IF;

    IF old_status IN (
        'healthy',
        'failed',
        'rolled_back'
    ) THEN
        RETURN FALSE;
    END IF;

    RETURN FALSE;
END
$$;

CREATE OR REPLACE FUNCTION
vpn_platform_guard_deployment_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT vpn_platform_status_transition_allowed(
        OLD.status,
        NEW.status
    ) THEN
        RAISE EXCEPTION
            'invalid deployment transition: % -> %',
            OLD.status,
            NEW.status
        USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS
    deployments_status_transition_guard
ON deployments;

CREATE TRIGGER
    deployments_status_transition_guard
BEFORE UPDATE OF status
ON deployments
FOR EACH ROW
WHEN (
    OLD.status IS DISTINCT FROM NEW.status
)
EXECUTE FUNCTION
    vpn_platform_guard_deployment_transition();

CREATE OR REPLACE FUNCTION
vpn_platform_guard_rollout_outcome_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT vpn_platform_status_transition_allowed(
        OLD.outcome_status,
        NEW.outcome_status
    ) THEN
        RAISE EXCEPTION
            'invalid rollout outcome transition: % -> %',
            OLD.outcome_status,
            NEW.outcome_status
        USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS
    rollout_outcome_transition_guard
ON rollout_plans;

CREATE TRIGGER
    rollout_outcome_transition_guard
BEFORE UPDATE OF outcome_status
ON rollout_plans
FOR EACH ROW
WHEN (
    OLD.outcome_status
        IS DISTINCT FROM
    NEW.outcome_status
)
EXECUTE FUNCTION
    vpn_platform_guard_rollout_outcome_transition();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'rollout_plans_outcome_requires_executed_chk'
    ) THEN
        ALTER TABLE rollout_plans
        ADD CONSTRAINT
            rollout_plans_outcome_requires_executed_chk
        CHECK (
            outcome_status IS NULL
            OR status = 'executed'
        )
        NOT VALID;
    END IF;
END
$$;

ALTER TABLE rollout_plans
VALIDATE CONSTRAINT
    rollout_plans_outcome_requires_executed_chk;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'rollout_plans_executed_requires_outcome_chk'
    ) THEN
        ALTER TABLE rollout_plans
        ADD CONSTRAINT
            rollout_plans_executed_requires_outcome_chk
        CHECK (
            status <> 'executed'
            OR outcome_status IS NOT NULL
        )
        NOT VALID;
    END IF;
END
$$;

ALTER TABLE rollout_plans
VALIDATE CONSTRAINT
    rollout_plans_executed_requires_outcome_chk;
