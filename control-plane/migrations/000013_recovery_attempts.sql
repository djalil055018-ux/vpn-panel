CREATE TABLE recovery_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    node_id UUID NOT NULL
        REFERENCES nodes(id)
        ON DELETE CASCADE,

    source_deployment_id UUID NOT NULL,
    source_generation BIGINT NOT NULL,
    source_deployment_status TEXT NOT NULL,

    base_desired_generation BIGINT NOT NULL,
    base_applied_generation BIGINT NOT NULL,
    proposed_generation BIGINT NOT NULL,

    core_type TEXT NOT NULL,

    target_core_release_id UUID
        REFERENCES core_releases(id),

    target_version TEXT,
    target_channel TEXT,

    status TEXT NOT NULL,

    blockers JSONB NOT NULL
        DEFAULT '[]'::jsonb,

    desired_state_preview JSONB,

    created_by TEXT NOT NULL
        DEFAULT 'control-plane',

    approved_by TEXT,
    approved_at TIMESTAMPTZ,

    executed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,

    failure_reason TEXT,

    deployment_id UUID,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    expires_at TIMESTAMPTZ NOT NULL
        DEFAULT now() + interval '1 hour',

    CONSTRAINT recovery_attempts_status_chk
        CHECK (
            status IN (
                'blocked',
                'planned',
                'approved',
                'executed',
                'cancelled',
                'failed',
                'stale'
            )
        ),

    CONSTRAINT recovery_attempts_source_status_chk
        CHECK (
            source_deployment_status IN (
                'pending',
                'applying',
                'healthy',
                'failed',
                'rolled_back'
            )
        ),

    CONSTRAINT recovery_attempts_blockers_chk
        CHECK (
            jsonb_typeof(blockers) = 'array'
        ),

    CONSTRAINT recovery_attempts_generation_sequence_chk
        CHECK (
            proposed_generation =
            base_desired_generation + 1
        ),

    CONSTRAINT recovery_attempts_expires_chk
        CHECK (
            expires_at > created_at
        ),

    CONSTRAINT recovery_attempts_active_source_generation_chk
        CHECK (
            status NOT IN (
                'planned',
                'approved',
                'executed'
            )
            OR
            source_generation =
            base_desired_generation
        ),

    CONSTRAINT recovery_attempts_active_source_status_chk
        CHECK (
            status NOT IN (
                'planned',
                'approved',
                'executed'
            )
            OR
            source_deployment_status = 'rolled_back'
        ),

    CONSTRAINT recovery_attempts_active_release_chk
        CHECK (
            status NOT IN (
                'planned',
                'approved',
                'executed'
            )
            OR
            target_core_release_id IS NOT NULL
        ),

    CONSTRAINT recovery_attempts_active_preview_chk
        CHECK (
            status NOT IN (
                'planned',
                'approved',
                'executed'
            )
            OR
            desired_state_preview IS NOT NULL
        ),

    CONSTRAINT recovery_attempts_executed_receipt_chk
        CHECK (
            status <> 'executed'
            OR deployment_id IS NOT NULL
        )
);

ALTER TABLE recovery_attempts
    ADD CONSTRAINT recovery_attempts_source_exact_fk
    FOREIGN KEY (
        source_deployment_id,
        node_id,
        source_generation
    )
    REFERENCES deployments(
        id,
        node_id,
        generation
    )
    ON DELETE RESTRICT;

ALTER TABLE recovery_attempts
    ADD CONSTRAINT recovery_attempts_deployment_exact_fk
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

CREATE INDEX recovery_attempts_node_created_idx
ON recovery_attempts(
    node_id,
    created_at DESC
);

CREATE INDEX recovery_attempts_status_idx
ON recovery_attempts(status);

CREATE INDEX recovery_attempts_expiry_idx
ON recovery_attempts(expires_at)
WHERE status IN (
    'planned',
    'approved'
);

CREATE INDEX recovery_attempts_target_release_idx
ON recovery_attempts(target_core_release_id)
WHERE target_core_release_id IS NOT NULL;

CREATE UNIQUE INDEX recovery_attempts_one_active_per_source_idx
ON recovery_attempts(source_deployment_id)
WHERE status IN (
    'planned',
    'approved'
);

CREATE UNIQUE INDEX recovery_attempts_one_active_per_node_idx
ON recovery_attempts(node_id)
WHERE status IN (
    'planned',
    'approved'
);

CREATE UNIQUE INDEX recovery_attempts_deployment_unique_idx
ON recovery_attempts(deployment_id)
WHERE deployment_id IS NOT NULL;
