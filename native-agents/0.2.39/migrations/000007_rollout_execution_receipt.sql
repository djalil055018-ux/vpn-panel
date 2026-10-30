ALTER TABLE rollout_plans
ADD COLUMN IF NOT EXISTS deployment_id UUID;

UPDATE rollout_plans rp
SET deployment_id = d.id
FROM deployments d
WHERE rp.status = 'executed'
  AND rp.deployment_id IS NULL
  AND d.node_id = rp.node_id
  AND d.generation = rp.proposed_generation;

CREATE UNIQUE INDEX IF NOT EXISTS
    rollout_plans_deployment_id_unique_idx
ON rollout_plans(deployment_id)
WHERE deployment_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS
    deployments_id_node_generation_unique_idx
ON deployments(
    id,
    node_id,
    generation
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'rollout_plans_deployment_exact_fk'
    ) THEN
        ALTER TABLE rollout_plans
        ADD CONSTRAINT rollout_plans_deployment_exact_fk
        FOREIGN KEY (
            deployment_id,
            node_id,
            proposed_generation
        )
        REFERENCES deployments(
            id,
            node_id,
            generation
        )
        ON DELETE RESTRICT;
    END IF;
END
$$;
