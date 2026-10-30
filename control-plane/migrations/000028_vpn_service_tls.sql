BEGIN;
ALTER TABLE node_certificates ADD CONSTRAINT node_certificates_id_tenant_node_unique UNIQUE(id,tenant_id,node_id);
ALTER TABLE vpn_services ADD CONSTRAINT vpn_services_id_tenant_node_unique UNIQUE(id,tenant_id,node_id);
CREATE TABLE vpn_service_tls (
    service_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    node_id UUID NOT NULL,
    certificate_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(service_id,tenant_id,node_id) REFERENCES vpn_services(id,tenant_id,node_id) ON DELETE CASCADE,
    FOREIGN KEY(certificate_id,tenant_id,node_id) REFERENCES node_certificates(id,tenant_id,node_id) ON DELETE RESTRICT
);
CREATE INDEX vpn_service_tls_certificate_idx ON vpn_service_tls(certificate_id);
COMMIT;
