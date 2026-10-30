BEGIN;

CREATE TABLE IF NOT EXISTS node_reboot_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'claimed', 'scheduled', 'failed')),
    requested_by TEXT NOT NULL DEFAULT '',
    owner_instance_id UUID,
    failure_code TEXT,
    requested_last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    scheduled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT node_reboot_jobs_failure_code_chk
        CHECK (failure_code IS NULL OR failure_code IN ('scheduler_unavailable', 'request_expired', 'node_not_ready', 'operation_in_progress'))
);

CREATE INDEX IF NOT EXISTS node_reboot_jobs_node_created_idx
    ON node_reboot_jobs(node_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS node_reboot_jobs_one_active_per_node_uidx
    ON node_reboot_jobs(node_id)
    WHERE status IN ('queued', 'claimed');

COMMIT;
