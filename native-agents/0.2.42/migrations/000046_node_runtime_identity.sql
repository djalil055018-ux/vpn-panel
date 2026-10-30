BEGIN;
ALTER TABLE nodes ADD COLUMN runtime_core TEXT NOT NULL DEFAULT 'xray'
 CHECK(runtime_core IN ('xray','hysteria2'));

CREATE FUNCTION protect_node_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.runtime_core IS DISTINCT FROM OLD.runtime_core THEN
  RAISE EXCEPTION 'node runtime selection is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER node_runtime_identity_immutable BEFORE UPDATE OF runtime_core ON nodes
 FOR EACH ROW EXECUTE FUNCTION protect_node_runtime_identity();

CREATE FUNCTION enforce_desired_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected TEXT; requested TEXT;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id;
 requested := NEW.document->'core'->>'type';
 -- Old recovery fixtures/records may omit the core. New Hysteria assignments
 -- require an explicit match, and no declared core may cross the node boundary.
 IF (requested IS NOT NULL OR selected='hysteria2') AND requested IS DISTINCT FROM selected THEN
  RAISE EXCEPTION 'desired runtime differs from node selection' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER desired_runtime_identity BEFORE INSERT OR UPDATE OF document,node_id ON desired_states
 FOR EACH ROW EXECUTE FUNCTION enforce_desired_runtime_identity();

CREATE FUNCTION enforce_service_runtime_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected TEXT;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id;
 IF (selected='hysteria2') IS DISTINCT FROM (NEW.protocol='hysteria2') THEN
  RAISE EXCEPTION 'service runtime differs from node selection' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='hysteria2' AND (NEW.transport<>'udp' OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'Hysteria requires UDP and TLS' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER service_runtime_identity BEFORE INSERT OR UPDATE OF node_id,protocol,transport,security ON vpn_services
 FOR EACH ROW EXECUTE FUNCTION enforce_service_runtime_identity();
CREATE UNIQUE INDEX hysteria_one_enabled_service ON vpn_services(node_id)
 WHERE protocol='hysteria2' AND enabled;
COMMIT;
