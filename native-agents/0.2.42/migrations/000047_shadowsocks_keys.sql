BEGIN;
CREATE TABLE vpn_service_shadowsocks (
 service_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 server_key text NOT NULL CHECK(length(server_key)=44),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE
);
CREATE TABLE vpn_client_shadowsocks_keys (
 client_id uuid NOT NULL,
 tenant_id uuid NOT NULL,
 credential_uuid uuid NOT NULL,
 client_key text NOT NULL CHECK(length(client_key)=44),
 PRIMARY KEY(client_id,credential_uuid),
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id) ON DELETE CASCADE
);
COMMIT;
