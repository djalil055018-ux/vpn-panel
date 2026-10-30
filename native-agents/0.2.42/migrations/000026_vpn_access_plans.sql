BEGIN;

CREATE TABLE vpn_access_plans (
    id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,
    code TEXT NOT NULL,

    enabled BOOLEAN NOT NULL
        DEFAULT true,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT vpn_access_plans_id_tenant_unique
        UNIQUE (id, tenant_id),

    CONSTRAINT vpn_access_plans_name_not_empty_chk
        CHECK (btrim(name) <> ''),

    CONSTRAINT vpn_access_plans_code_not_empty_chk
        CHECK (btrim(code) <> ''),

    CONSTRAINT vpn_access_plans_code_format_chk
        CHECK (
            code = lower(code)
            AND code ~ '^[a-z0-9][a-z0-9_-]{0,63}$'
        ),

    CONSTRAINT vpn_access_plans_tenant_code_unique
        UNIQUE (tenant_id, code)
);

CREATE INDEX vpn_access_plans_tenant_idx
ON vpn_access_plans(tenant_id);

CREATE INDEX vpn_access_plans_enabled_idx
ON vpn_access_plans(tenant_id, enabled);


CREATE TABLE vpn_access_plan_services (
    tenant_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    service_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    PRIMARY KEY (
        plan_id,
        service_id
    ),

    CONSTRAINT vpn_access_plan_services_plan_tenant_fk
        FOREIGN KEY (
            plan_id,
            tenant_id
        )
        REFERENCES vpn_access_plans(
            id,
            tenant_id
        )
        ON DELETE CASCADE,

    CONSTRAINT vpn_access_plan_services_service_tenant_fk
        FOREIGN KEY (
            service_id,
            tenant_id
        )
        REFERENCES vpn_services(
            id,
            tenant_id
        )
        ON DELETE CASCADE
);

CREATE INDEX vpn_access_plan_services_tenant_idx
ON vpn_access_plan_services(tenant_id);

CREATE INDEX vpn_access_plan_services_service_idx
ON vpn_access_plan_services(service_id);


CREATE TABLE vpn_client_access_plans (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    plan_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    PRIMARY KEY (
        client_id,
        plan_id
    ),

    CONSTRAINT vpn_client_access_plans_client_tenant_fk
        FOREIGN KEY (
            client_id,
            tenant_id
        )
        REFERENCES vpn_clients(
            id,
            tenant_id
        )
        ON DELETE CASCADE,

    CONSTRAINT vpn_client_access_plans_plan_tenant_fk
        FOREIGN KEY (
            plan_id,
            tenant_id
        )
        REFERENCES vpn_access_plans(
            id,
            tenant_id
        )
        ON DELETE CASCADE
);

CREATE INDEX vpn_client_access_plans_tenant_idx
ON vpn_client_access_plans(tenant_id);

CREATE INDEX vpn_client_access_plans_plan_idx
ON vpn_client_access_plans(plan_id);

COMMIT;
