BEGIN;
ALTER TABLE nodes DROP CONSTRAINT nodes_runtime_core_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_runtime_core_check CHECK(runtime_core IN ('xray','hysteria2','openvpn'));
CREATE OR REPLACE FUNCTION enforce_service_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected text;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id;
 IF (selected='hysteria2') IS DISTINCT FROM (NEW.protocol='hysteria2') OR (selected='openvpn') IS DISTINCT FROM (NEW.protocol='openvpn') THEN
  RAISE EXCEPTION 'service runtime differs from node selection' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='hysteria2' AND (NEW.transport<>'udp' OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'Hysteria requires UDP and TLS' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='openvpn' AND (NEW.transport NOT IN ('udp','tcp') OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'OpenVPN requires TCP or UDP and TLS' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE UNIQUE INDEX openvpn_one_enabled_service ON vpn_services(node_id) WHERE protocol='openvpn' AND enabled;
CREATE TABLE vpn_service_openvpn (
 service_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 ca_certificate text NOT NULL,
 ca_private_key text NOT NULL,
 server_certificate text NOT NULL,
 server_private_key text NOT NULL,
 tls_crypt_key text NOT NULL,
 next_refresh_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE
);
CREATE TABLE vpn_client_openvpn_certificates (
 service_id uuid NOT NULL,
 client_id uuid NOT NULL,
 tenant_id uuid NOT NULL,
 credential_uuid uuid NOT NULL,
 serial text NOT NULL CHECK(serial ~ '^[1-9][0-9]{0,39}$'),
 certificate text NOT NULL,
 private_key text NOT NULL,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(service_id,serial),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE,
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id) ON DELETE CASCADE
);
CREATE INDEX openvpn_client_certificate_lookup ON vpn_client_openvpn_certificates(service_id,client_id,credential_uuid,created_at DESC);
COMMIT;
