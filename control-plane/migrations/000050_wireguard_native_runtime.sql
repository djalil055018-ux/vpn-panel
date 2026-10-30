BEGIN;
ALTER TABLE nodes DROP CONSTRAINT nodes_runtime_core_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_runtime_core_check CHECK(runtime_core IN ('xray','hysteria2','openvpn','wireguard'));
CREATE OR REPLACE FUNCTION enforce_service_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected text;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id FOR UPDATE;
 IF (selected='hysteria2') IS DISTINCT FROM (NEW.protocol='hysteria2') OR (selected='openvpn') IS DISTINCT FROM (NEW.protocol='openvpn') OR (selected='wireguard' AND NEW.protocol<>'wireguard') THEN
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
 RETURN NEW;
END;
$$;
COMMIT;
