DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'deployments_status_chk'
    ) THEN
        ALTER TABLE deployments
        ADD CONSTRAINT deployments_status_chk
        CHECK (
            status IN (
                'pending',
                'applying',
                'healthy',
                'failed',
                'rolled_back'
            )
        )
        NOT VALID;
    END IF;
END
$$;

ALTER TABLE deployments
VALIDATE CONSTRAINT deployments_status_chk;
