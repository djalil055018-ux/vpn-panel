BEGIN;

CREATE TABLE execution_fence_requests (
    id UUID PRIMARY KEY,

    tenant_id UUID NOT NULL,
    node_id UUID NOT NULL,

    deployment_id UUID NOT NULL,
    generation BIGINT NOT NULL,

    execution_id UUID NOT NULL,
    execution_epoch BIGINT NOT NULL,

    state TEXT NOT NULL DEFAULT 'requested',

    target_owner_instance_id UUID NOT NULL,

    reason TEXT NOT NULL,

    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    acknowledged_at TIMESTAMPTZ,
    acknowledged_by_instance_id UUID,

    cancelled_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT execution_fence_requests_state_chk
    CHECK (
        state IN (
            'requested',
            'acknowledged',
            'cancelled'
        )
    ),

    CONSTRAINT execution_fence_requests_generation_chk
    CHECK (
        generation >= 1
    ),

    CONSTRAINT execution_fence_requests_epoch_chk
    CHECK (
        execution_epoch >= 1
    ),

    CONSTRAINT execution_fence_requests_reason_chk
    CHECK (
        NULLIF(
            btrim(reason),
            ''
        ) IS NOT NULL
    ),

    CONSTRAINT execution_fence_requests_ack_chk
    CHECK (
        state <> 'acknowledged'
        OR (
            acknowledged_at IS NOT NULL
            AND acknowledged_by_instance_id IS NOT NULL
        )
    ),

    CONSTRAINT execution_fence_requests_cancel_chk
    CHECK (
        state <> 'cancelled'
        OR cancelled_at IS NOT NULL
    ),

    CONSTRAINT execution_fence_requests_exact_fk
    FOREIGN KEY (
        deployment_id,
        node_id,
        generation,
        execution_id,
        execution_epoch
    )
    REFERENCES deployments(
        id,
        node_id,
        generation,
        execution_id,
        execution_epoch
    )
    ON DELETE CASCADE,

    CONSTRAINT execution_fence_requests_tenant_fk
    FOREIGN KEY (
        tenant_id
    )
    REFERENCES tenants(id)
    ON DELETE CASCADE,

    CONSTRAINT execution_fence_requests_node_fk
    FOREIGN KEY (
        node_id
    )
    REFERENCES nodes(id)
    ON DELETE CASCADE
);

-- Only one outstanding fence request may exist for one
-- immutable physical execution at a time.
CREATE UNIQUE INDEX
execution_fence_requests_one_requested_execution_idx
ON execution_fence_requests(
    deployment_id
)
WHERE state = 'requested';

CREATE INDEX
execution_fence_requests_node_requested_idx
ON execution_fence_requests(
    node_id,
    requested_at
)
WHERE state = 'requested';

CREATE INDEX
execution_fence_requests_execution_idx
ON execution_fence_requests(
    execution_id,
    execution_epoch
);

CREATE OR REPLACE FUNCTION
vpn_platform_guard_execution_fence_request_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'requested'
       AND NEW.state IN (
            'acknowledged',
            'cancelled'
       )
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'invalid execution fence request transition: % -> %',
        OLD.state,
        NEW.state
        USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER execution_fence_request_transition_guard
BEFORE UPDATE OF state
ON execution_fence_requests
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state)
EXECUTE FUNCTION
vpn_platform_guard_execution_fence_request_transition();

-- Exact execution identity and target physical owner are immutable.
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
    THEN
        RAISE EXCEPTION
            'execution fence request identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_fence_request_identity_guard
BEFORE UPDATE ON execution_fence_requests
FOR EACH ROW
EXECUTE FUNCTION
vpn_platform_guard_execution_fence_request_identity();

COMMIT;
