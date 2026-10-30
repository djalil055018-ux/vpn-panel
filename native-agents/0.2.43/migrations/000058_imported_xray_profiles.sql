BEGIN;

-- TCP/443 and UDP/443 are different listeners in a mixed imported profile.
-- Combined or unknown transports reserve both families, preserving a strict
-- conflict check for protocols that have not declared a narrower socket type.
ALTER TABLE vpn_services DROP CONSTRAINT vpn_services_bind_unique;
CREATE UNIQUE INDEX vpn_services_tcp_bind_unique ON vpn_services(node_id,listen,port)
 WHERE transport<>'udp';
CREATE UNIQUE INDEX vpn_services_udp_bind_unique ON vpn_services(node_id,listen,port)
 WHERE transport NOT IN ('tcp','raw','xhttp','ws','grpc','tcp,gre');

-- Only an owner preparation/cutover workflow may populate this registry.
-- It binds the projected graph to immutable source bytes and one native node.
CREATE TABLE node_xray_profiles (
 node_id UUID PRIMARY KEY,
 tenant_id UUID NOT NULL,
 import_id UUID NOT NULL,
 inventory_sha256 TEXT NOT NULL,
 source_node_id UUID NOT NULL,
 source_profile_id UUID NOT NULL,
 profile_sha256 TEXT NOT NULL CHECK(profile_sha256 ~ '^[0-9a-f]{64}$'),
 profile JSONB NOT NULL CHECK(jsonb_typeof(profile)='object' AND octet_length(profile::text)<=2097152),
 state TEXT NOT NULL DEFAULT 'prepared' CHECK(state IN ('prepared','active')),
 adoption_sha256 TEXT CHECK(adoption_sha256 ~ '^[0-9a-f]{64}$'),
 prepared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 activated_at TIMESTAMPTZ,
 UNIQUE(node_id,tenant_id),
 UNIQUE(import_id,source_node_id),
 FOREIGN KEY(node_id,tenant_id) REFERENCES nodes(id,tenant_id) ON DELETE RESTRICT,
 FOREIGN KEY(import_id,tenant_id) REFERENCES remnawave_imports(id,tenant_id) ON DELETE RESTRICT,
 FOREIGN KEY(import_id,inventory_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256),
 CHECK(profile->>'sha256'=profile_sha256),
 CHECK(state<>'active' OR (adoption_sha256 IS NOT NULL AND activated_at IS NOT NULL))
);
CREATE TABLE node_xray_profile_bindings (
 node_id UUID NOT NULL,
 tenant_id UUID NOT NULL,
 service_id UUID PRIMARY KEY,
 source_inbound_id UUID NOT NULL,
 source_enabled BOOLEAN NOT NULL,
 inbound_tag TEXT NOT NULL CHECK(length(inbound_tag) BETWEEN 1 AND 256),
 service_spec JSONB NOT NULL CHECK(jsonb_typeof(service_spec)='object' AND octet_length(service_spec::text)<=16384),
 UNIQUE(node_id,inbound_tag),
 UNIQUE(node_id,source_inbound_id),
 FOREIGN KEY(node_id,tenant_id) REFERENCES node_xray_profiles(node_id,tenant_id) ON DELETE RESTRICT,
 FOREIGN KEY(service_id,tenant_id,node_id) REFERENCES vpn_services(id,tenant_id,node_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(service_spec->>'id'=service_id::text),
 CHECK(NOT service_spec ? 'clients' OR service_spec->'clients'='[]'::jsonb),
 CHECK(NOT (COALESCE(service_spec->'reality','{}') ? 'private_key')),
 CHECK(NOT (COALESCE(service_spec->'tls','{}') ?| ARRAY['certificate_file','key_file']))
);

CREATE FUNCTION immutable_xray_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'imported Xray profile identity is immutable' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER xray_profile_immutable BEFORE UPDATE OF node_id,tenant_id,import_id,inventory_sha256,source_node_id,source_profile_id,profile_sha256,profile ON node_xray_profiles
 FOR EACH ROW EXECUTE FUNCTION immutable_xray_profile();
CREATE TRIGGER xray_binding_immutable BEFORE UPDATE OR DELETE ON node_xray_profile_bindings
 FOR EACH ROW EXECUTE FUNCTION immutable_xray_profile();
CREATE FUNCTION enforce_xray_activation_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state='active' AND NEW.state<>'active' THEN
  RAISE EXCEPTION 'an adopted Xray profile cannot return to preparation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER xray_activation_monotonic BEFORE UPDATE OF state ON node_xray_profiles
 FOR EACH ROW EXECUTE FUNCTION enforce_xray_activation_monotonic();

-- Source Short IDs may be empty. Ordinary service writes still require the
-- existing 16-hex form; only an exact registered imported binding has an exception.
ALTER TABLE vpn_service_reality DROP CONSTRAINT vpn_service_reality_short_id_chk;
ALTER TABLE vpn_service_reality ADD CONSTRAINT vpn_service_reality_short_id_chk CHECK(short_id ~ '^([0-9a-f]{2}){0,8}$');
CREATE FUNCTION enforce_imported_reality_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expected JSONB; public TEXT;
BEGIN
 SELECT b.service_spec->'reality', j.value->>'reality_public_key' INTO expected,public
 FROM node_xray_profile_bindings b JOIN node_xray_profiles p USING(node_id,tenant_id)
 CROSS JOIN LATERAL jsonb_array_elements(p.profile->'bindings') j
 WHERE b.service_id=NEW.service_id AND j.value->>'service_id'=b.service_id::text;
 IF FOUND THEN
  IF expected IS NULL OR (NEW.destination,NEW.server_name,NEW.short_id,NEW.secret_ref) IS DISTINCT FROM
     (expected->>'destination',expected->>'server_name',expected->>'short_id',expected->>'secret_ref')
     OR (NEW.public_key IS NOT NULL AND NEW.public_key IS DISTINCT FROM public) THEN
   RAISE EXCEPTION 'imported Reality identity differs from reviewed source' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.short_id !~ '^[0-9a-f]{16}$' THEN
  RAISE EXCEPTION 'ordinary Reality service requires a 16-hex Short ID' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER imported_reality_identity BEFORE INSERT OR UPDATE ON vpn_service_reality
 FOR EACH ROW EXECUTE FUNCTION enforce_imported_reality_identity();

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

CREATE FUNCTION enforce_imported_service_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE profile_state TEXT; expected JSONB;
BEGIN
 SELECT state INTO profile_state FROM node_xray_profiles WHERE node_id=NEW.node_id;
 IF FOUND THEN
  SELECT service_spec INTO expected FROM node_xray_profile_bindings
   WHERE service_id=NEW.id AND node_id=NEW.node_id AND tenant_id=NEW.tenant_id;
  IF NOT FOUND OR (NEW.protocol,NEW.listen,NEW.port,NEW.transport,NEW.security) IS DISTINCT FROM
    (expected->>'protocol',expected->>'listen',(expected->>'port')::integer,expected->>'transport',expected->>'security')
    OR (NEW.enabled AND profile_state<>'active') THEN
   RAISE EXCEPTION 'imported service differs from reviewed binding or is not active' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER imported_service_identity BEFORE INSERT OR UPDATE ON vpn_services
 FOR EACH ROW EXECUTE FUNCTION enforce_imported_service_identity();
COMMIT;
