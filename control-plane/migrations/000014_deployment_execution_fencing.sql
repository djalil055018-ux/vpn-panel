BEGIN;

ALTER TABLE nodes
    ADD COLUMN execution_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_execution_epoch_chk
    CHECK (execution_epoch >= 0);


ALTER TABLE deployments
    ADD COLUMN execution_id UUID,
    ADD COLUMN execution_epoch BIGINT;


-- Existing deployments receive deterministic monotonic
-- epochs based on their immutable generation history.
-- The epoch is a separate concept even though the initial
-- historical backfill uses generation as its seed.
UPDATE deployments
SET
    execution_id = gen_random_uuid(),
    execution_epoch = generation
WHERE execution_id IS NULL
   OR execution_epoch IS NULL;


-- Advance every node's allocator beyond all historical
-- deployment execution epochs.
UPDATE nodes n
SET execution_epoch = GREATEST(
    n.execution_epoch,
    COALESCE(
        (
            SELECT MAX(d.execution_epoch)
            FROM deployments d
            WHERE d.node_id = n.id
        ),
        0
    )
);


ALTER TABLE deployments
    ALTER COLUMN execution_id SET NOT NULL,
    ALTER COLUMN execution_id SET DEFAULT gen_random_uuid(),
    ALTER COLUMN execution_epoch SET NOT NULL;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_execution_epoch_chk
    CHECK (execution_epoch >= 1);


CREATE UNIQUE INDEX deployments_execution_id_unique_idx
ON deployments(execution_id);

CREATE UNIQUE INDEX deployments_node_execution_epoch_unique_idx
ON deployments(node_id, execution_epoch);

CREATE UNIQUE INDEX deployments_execution_identity_unique_idx
ON deployments(
    id,
    node_id,
    generation,
    execution_id,
    execution_epoch
);


-- New deployments that do not explicitly supply an epoch
-- receive one atomically from the owning node.
CREATE OR REPLACE FUNCTION
vpn_platform_assign_deployment_execution_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.execution_id IS NULL THEN
        NEW.execution_id := gen_random_uuid();
    END IF;

    IF NEW.execution_epoch IS NULL THEN
        UPDATE nodes
        SET execution_epoch = execution_epoch + 1
        WHERE id = NEW.node_id
        RETURNING execution_epoch
        INTO NEW.execution_epoch;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'deployment node % does not exist',
                NEW.node_id
                USING ERRCODE = '23503';
        END IF;
    ELSE
        UPDATE nodes
        SET execution_epoch = GREATEST(
            execution_epoch,
            NEW.execution_epoch
        )
        WHERE id = NEW.node_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'deployment node % does not exist',
                NEW.node_id
                USING ERRCODE = '23503';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER deployments_execution_identity_assign
BEFORE INSERT ON deployments
FOR EACH ROW
EXECUTE FUNCTION
vpn_platform_assign_deployment_execution_identity();


-- execution_id and execution_epoch identify the physical
-- immutable attempt and can never be rewritten later.
CREATE OR REPLACE FUNCTION
vpn_platform_guard_execution_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.execution_id IS DISTINCT FROM NEW.execution_id
       OR OLD.execution_epoch IS DISTINCT FROM NEW.execution_epoch
    THEN
        RAISE EXCEPTION
            'deployment execution identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER deployments_execution_identity_guard
BEFORE UPDATE OF execution_id, execution_epoch
ON deployments
FOR EACH ROW
EXECUTE FUNCTION
vpn_platform_guard_execution_identity();


CREATE TABLE deployment_execution_leases (
    deployment_id UUID PRIMARY KEY,

    node_id UUID NOT NULL,
    generation BIGINT NOT NULL,

    execution_id UUID NOT NULL,
    execution_epoch BIGINT NOT NULL,

    state TEXT NOT NULL DEFAULT 'unclaimed',

    owner_instance_id UUID,

    lease_token_hash TEXT,

    claimed_at TIMESTAMPTZ,
    renewed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,

    fenced_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    fencing_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT deployment_execution_leases_state_chk
    CHECK (
        state IN (
            'unclaimed',
            'active',
            'fenced',
            'completed'
        )
    ),

    CONSTRAINT deployment_execution_leases_epoch_chk
    CHECK (
        execution_epoch >= 1
    ),

    CONSTRAINT deployment_execution_leases_active_chk
    CHECK (
        state <> 'active'
        OR (
            owner_instance_id IS NOT NULL
            AND lease_token_hash IS NOT NULL
            AND claimed_at IS NOT NULL
            AND renewed_at IS NOT NULL
            AND lease_expires_at IS NOT NULL
        )
    ),

    CONSTRAINT deployment_execution_leases_fenced_chk
    CHECK (
        state <> 'fenced'
        OR (
            fenced_at IS NOT NULL
            AND NULLIF(
                btrim(fencing_reason),
                ''
            ) IS NOT NULL
        )
    ),

    CONSTRAINT deployment_execution_leases_completed_chk
    CHECK (
        state <> 'completed'
        OR completed_at IS NOT NULL
    ),

    CONSTRAINT deployment_execution_leases_exact_fk
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
    ON DELETE CASCADE
);


CREATE UNIQUE INDEX deployment_execution_leases_execution_id_idx
ON deployment_execution_leases(execution_id);

CREATE UNIQUE INDEX deployment_execution_leases_node_epoch_idx
ON deployment_execution_leases(
    node_id,
    execution_epoch
);

CREATE INDEX deployment_execution_leases_active_expiry_idx
ON deployment_execution_leases(
    lease_expires_at,
    deployment_id
)
WHERE state = 'active';


CREATE OR REPLACE FUNCTION
vpn_platform_guard_execution_lease_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'unclaimed'
       AND NEW.state IN (
            'active',
            'fenced'
       )
    THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'active'
       AND NEW.state IN (
            'fenced',
            'completed'
       )
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'invalid execution lease transition: % -> %',
        OLD.state,
        NEW.state
        USING ERRCODE = '23514';
END;
$$;


CREATE TRIGGER deployment_execution_lease_transition_guard
BEFORE UPDATE OF state
ON deployment_execution_leases
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state)
EXECUTE FUNCTION
vpn_platform_guard_execution_lease_transition();


COMMIT;
