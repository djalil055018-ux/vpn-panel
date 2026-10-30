BEGIN;

-- Remove the stale TEST-NODE-01 created before the real agent registration.
DELETE FROM nodes
WHERE id = 'cc7801ae-b156-4c36-9433-556fe86d3866'
  AND status = 'pending'
  AND desired_generation = 0
  AND applied_generation = 0;

-- One tenant must never have two nodes with the same name.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'nodes_tenant_name_unique'
    ) THEN
        ALTER TABLE nodes
        ADD CONSTRAINT nodes_tenant_name_unique
        UNIQUE (tenant_id, name);
    END IF;
END
$$;

COMMIT;
