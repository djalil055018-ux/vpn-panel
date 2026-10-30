BEGIN;
ALTER TABLE nodes DROP CONSTRAINT nodes_runtime_core_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_runtime_core_check CHECK(runtime_core IN ('xray','hysteria2','openvpn','wireguard','pptp'));

CREATE TABLE vpn_client_pptp (
 service_id uuid NOT NULL,
 client_id uuid NOT NULL,
 tenant_id uuid NOT NULL,
 credential_uuid uuid NOT NULL,
 password text NOT NULL CHECK(password ~ '^[a-f0-9]{64}$'),
 address_index integer NOT NULL CHECK(address_index BETWEEN 2 AND 253),
 PRIMARY KEY(service_id,client_id),
 UNIQUE(service_id,address_index),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE,
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION enforce_service_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected text;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id FOR UPDATE;
 IF (selected='hysteria2') IS DISTINCT FROM (NEW.protocol='hysteria2') OR (selected='openvpn') IS DISTINCT FROM (NEW.protocol='openvpn') OR (selected='pptp') IS DISTINCT FROM (NEW.protocol='pptp') OR (selected='wireguard' AND NEW.protocol<>'wireguard') THEN
  RAISE EXCEPTION 'service runtime differs from node selection' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='hysteria2' AND (NEW.transport<>'udp' OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'Hysteria requires UDP and TLS' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='openvpn' AND (NEW.transport NOT IN ('udp','tcp') OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'OpenVPN requires TCP or UDP and TLS' USING ERRCODE='23514';
 END IF;
 IF selected='wireguard' THEN
  IF NEW.transport<>'udp' OR NEW.security<>'wireguard' OR NEW.listen NOT IN ('0.0.0.0','::') THEN
   RAISE EXCEPTION 'native WireGuard requires wildcard UDP' USING ERRCODE='23514';
  END IF;
  IF NEW.enabled AND EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.node_id AND id<>NEW.id AND enabled) THEN
   RAISE EXCEPTION 'native WireGuard allows one enabled service' USING ERRCODE='23514';
  END IF;
 END IF;
 IF selected='pptp' THEN
  IF NEW.transport<>'tcp,gre' OR NEW.security<>'mppe' OR NEW.port<>1723 OR (NEW.public_port IS NOT NULL AND NEW.public_port<>1723) THEN
   RAISE EXCEPTION 'PPTP requires TCP1723, GRE and MPPE' USING ERRCODE='23514';
  END IF;
  IF NEW.enabled AND EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.node_id AND id<>NEW.id AND enabled) THEN
   RAISE EXCEPTION 'PPTP allows one enabled service per node' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
COMMIT;
