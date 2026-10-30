BEGIN;
ALTER TABLE nodes DROP CONSTRAINT nodes_runtime_core_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_runtime_core_check
 CHECK(runtime_core IN ('xray','hysteria2','openvpn','wireguard','amneziawg','pptp'));

-- Shared obfuscation settings are private server state. Public service metadata
-- exposes the dialect only, never the header protection key or client keys.
CREATE TABLE vpn_service_amneziawg (
 service_id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL,
 version text NOT NULL CHECK(version IN ('1.0','1.5','2.0','3.0','3.1')),
 settings jsonb NOT NULL CHECK(jsonb_typeof(settings)='object' AND octet_length(settings::text)<=32768),
 updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id) ON DELETE CASCADE,
 CHECK(jsonb_typeof(settings->'version')='string' AND settings->>'version' IS NOT NULL AND settings->>'version'=version)
);

CREATE FUNCTION enforce_amneziawg_settings_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
  WHERE s.id=NEW.service_id AND s.tenant_id=NEW.tenant_id AND s.protocol='amneziawg' AND n.runtime_core='amneziawg') THEN
  RAISE EXCEPTION 'AmneziaWG settings require their own node runtime' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER amneziawg_settings_identity BEFORE INSERT OR UPDATE ON vpn_service_amneziawg
 FOR EACH ROW EXECUTE FUNCTION enforce_amneziawg_settings_identity();

CREATE OR REPLACE FUNCTION enforce_service_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected TEXT; imported BOOLEAN;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id FOR UPDATE;
 imported := selected='xray' AND EXISTS(
  SELECT 1 FROM node_xray_profile_bindings b WHERE b.service_id=NEW.id AND b.node_id=NEW.node_id
   AND b.tenant_id=NEW.tenant_id AND b.service_spec->>'protocol'=NEW.protocol
   AND b.service_spec->>'transport'=NEW.transport AND b.service_spec->>'security'=NEW.security);
 IF ((selected='hysteria2') IS DISTINCT FROM (NEW.protocol='hysteria2') AND NOT imported)
    OR (selected='openvpn') IS DISTINCT FROM (NEW.protocol='openvpn')
    OR (selected='pptp') IS DISTINCT FROM (NEW.protocol='pptp')
    OR (selected='amneziawg') IS DISTINCT FROM (NEW.protocol='amneziawg')
    OR (selected='wireguard' AND NEW.protocol<>'wireguard') THEN
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
 IF selected='amneziawg' THEN
  IF NEW.transport<>'udp' OR NEW.security<>'amneziawg' OR NEW.listen NOT IN ('0.0.0.0','::') THEN
   RAISE EXCEPTION 'AmneziaWG requires wildcard UDP' USING ERRCODE='23514';
  END IF;
  IF NEW.enabled AND EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.node_id AND id<>NEW.id AND enabled) THEN
   RAISE EXCEPTION 'AmneziaWG allows one enabled service' USING ERRCODE='23514';
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
