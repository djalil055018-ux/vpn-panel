BEGIN;

-- A node may have only one physically active execution owner.
CREATE UNIQUE INDEX deployment_execution_leases_one_active_per_node_idx
ON deployment_execution_leases(node_id)
WHERE state = 'active';

-- Active lease chronology must always be internally consistent.
ALTER TABLE deployment_execution_leases
ADD CONSTRAINT deployment_execution_leases_active_time_chk
CHECK (
    state <> 'active'
    OR (
        claimed_at IS NOT NULL
        AND renewed_at IS NOT NULL
        AND lease_expires_at IS NOT NULL
        AND renewed_at >= claimed_at
        AND lease_expires_at > renewed_at
    )
);

-- Once a lease is completed it must not simultaneously be fenced.
ALTER TABLE deployment_execution_leases
ADD CONSTRAINT deployment_execution_leases_terminal_time_chk
CHECK (
    NOT (
        completed_at IS NOT NULL
        AND fenced_at IS NOT NULL
    )
);

COMMIT;
