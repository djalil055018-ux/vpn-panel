BEGIN;
CREATE TABLE vpn_service_wireguard (
 service_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 private_key text NOT NULL CHECK(length(private_key)=44),
 public_key text NOT NULL CHECK(length(public_key)=44),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE
);
CREATE TABLE vpn_client_wireguard (
 service_id uuid NOT NULL,
 client_id uuid NOT NULL,
 tenant_id uuid NOT NULL,
 credential_uuid uuid NOT NULL,
 private_key text NOT NULL CHECK(length(private_key)=44),
 public_key text NOT NULL CHECK(length(public_key)=44),
 preshared_key text NOT NULL CHECK(length(preshared_key)=44),
 address_index integer NOT NULL CHECK(address_index BETWEEN 2 AND 65534),
 PRIMARY KEY(service_id,client_id),
 UNIQUE(service_id,address_index),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE,
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id) ON DELETE CASCADE
);
COMMIT;
