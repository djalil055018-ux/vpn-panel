BEGIN;

ALTER TABLE nodes
ADD CONSTRAINT nodes_id_tenant_unique
UNIQUE (id, tenant_id);

ALTER TABLE vpn_clients
ADD CONSTRAINT vpn_clients_id_tenant_unique
UNIQUE (id, tenant_id);

CREATE TABLE vpn_services (
    id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

    tenant_id UUID NOT NULL,

    node_id UUID NOT NULL,

    name TEXT NOT NULL,

    protocol TEXT NOT NULL,

    listen TEXT NOT NULL
        DEFAULT '0.0.0.0',

    port INTEGER NOT NULL,

    transport TEXT NOT NULL,

    security TEXT NOT NULL,

    public_address TEXT,

    public_port INTEGER,

    enabled BOOLEAN NOT NULL
        DEFAULT true,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    CONSTRAINT vpn_services_node_tenant_fk
        FOREIGN KEY (node_id, tenant_id)
        REFERENCES nodes(id, tenant_id)
        ON DELETE CASCADE,

    CONSTRAINT vpn_services_id_tenant_unique
        UNIQUE (id, tenant_id),

    CONSTRAINT vpn_services_name_not_empty_chk
        CHECK (btrim(name) <> ''),

    CONSTRAINT vpn_services_protocol_not_empty_chk
        CHECK (btrim(protocol) <> ''),

    CONSTRAINT vpn_services_listen_not_empty_chk
        CHECK (btrim(listen) <> ''),

    CONSTRAINT vpn_services_transport_not_empty_chk
        CHECK (btrim(transport) <> ''),

    CONSTRAINT vpn_services_security_not_empty_chk
        CHECK (btrim(security) <> ''),

    CONSTRAINT vpn_services_port_chk
        CHECK (
            port >= 1
            AND port <= 65535
        ),

    CONSTRAINT vpn_services_public_endpoint_chk
        CHECK (
            (
                public_address IS NULL
                AND public_port IS NULL
            )
            OR
            (
                public_address IS NOT NULL
                AND btrim(public_address) <> ''
                AND public_port >= 1
                AND public_port <= 65535
            )
        ),

    CONSTRAINT vpn_services_bind_unique
        UNIQUE (
            node_id,
            listen,
            port
        )
);

CREATE INDEX vpn_services_tenant_idx
ON vpn_services(tenant_id);

CREATE INDEX vpn_services_node_idx
ON vpn_services(node_id);

CREATE TABLE vpn_client_services (
    tenant_id UUID NOT NULL,

    client_id UUID NOT NULL,

    service_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT now(),

    PRIMARY KEY (
        client_id,
        service_id
    ),

    CONSTRAINT vpn_client_services_client_tenant_fk
        FOREIGN KEY (
            client_id,
            tenant_id
        )
        REFERENCES vpn_clients(
            id,
            tenant_id
        )
        ON DELETE CASCADE,

    CONSTRAINT vpn_client_services_service_tenant_fk
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

CREATE INDEX vpn_client_services_tenant_idx
ON vpn_client_services(tenant_id);

CREATE INDEX vpn_client_services_service_idx
ON vpn_client_services(service_id);

COMMIT;
