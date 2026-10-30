BEGIN;

-- Keep UUID ownership consistent with the rest of the platform.
ALTER TABLE execution_fence_requests
ALTER COLUMN id
SET DEFAULT gen_random_uuid();

-- Terminal timestamps must describe exactly one terminal state.
ALTER TABLE execution_fence_requests
ADD CONSTRAINT execution_fence_requests_terminal_exclusive_chk
CHECK (
    NOT (
        acknowledged_at IS NOT NULL
        AND cancelled_at IS NOT NULL
    )
);

-- requested:
--   no terminal metadata
--
-- acknowledged:
--   acknowledgement metadata present,
--   cancellation metadata absent
--
-- cancelled:
--   cancellation metadata present,
--   acknowledgement metadata absent
ALTER TABLE execution_fence_requests
ADD CONSTRAINT execution_fence_requests_state_metadata_chk
CHECK (
    (
        state = 'requested'
        AND acknowledged_at IS NULL
        AND acknowledged_by_instance_id IS NULL
        AND cancelled_at IS NULL
    )
    OR
    (
        state = 'acknowledged'
        AND acknowledged_at IS NOT NULL
        AND acknowledged_by_instance_id IS NOT NULL
        AND cancelled_at IS NULL
    )
    OR
    (
        state = 'cancelled'
        AND acknowledged_at IS NULL
        AND acknowledged_by_instance_id IS NULL
        AND cancelled_at IS NOT NULL
    )
);

-- The physical execution target and the reason for fencing
-- are immutable after request creation.
CREATE OR REPLACE FUNCTION
vpn_platform_guard_execution_fence_request_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.node_id IS DISTINCT FROM NEW.node_id
       OR OLD.deployment_id IS DISTINCT FROM NEW.deployment_id
       OR OLD.generation IS DISTINCT FROM NEW.generation
       OR OLD.execution_id IS DISTINCT FROM NEW.execution_id
       OR OLD.execution_epoch IS DISTINCT FROM NEW.execution_epoch
       OR OLD.target_owner_instance_id IS DISTINCT FROM NEW.target_owner_instance_id
       OR OLD.reason IS DISTINCT FROM NEW.reason
       OR OLD.requested_at IS DISTINCT FROM NEW.requested_at
    THEN
        RAISE EXCEPTION
            'execution fence request identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

COMMIT;
