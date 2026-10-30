BEGIN;

ALTER TABLE node_certificates ADD CONSTRAINT node_certificates_native_identity_unique UNIQUE(id,node_id,tenant_id);
CREATE TABLE imported_tls_certificates (
 certificate_id UUID PRIMARY KEY,
 node_id UUID NOT NULL,
 tenant_id UUID NOT NULL,
 import_id UUID NOT NULL,
 inventory_sha256 TEXT NOT NULL,
 source_node_id UUID NOT NULL,
 domain TEXT NOT NULL,
 chain_sha256 TEXT NOT NULL CHECK(chain_sha256 ~ '^[0-9a-f]{64}$'),
 fingerprint_sha256 TEXT NOT NULL CHECK(fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
 adoption_sha256 TEXT NOT NULL CHECK(adoption_sha256 ~ '^[0-9a-f]{64}$'),
 prepared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(node_id,domain),
 FOREIGN KEY(certificate_id,node_id,tenant_id) REFERENCES node_certificates(id,node_id,tenant_id) ON DELETE RESTRICT,
 FOREIGN KEY(import_id,tenant_id) REFERENCES remnawave_imports(id,tenant_id) ON DELETE RESTRICT,
 FOREIGN KEY(import_id,inventory_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256)
);
CREATE TRIGGER imported_tls_provenance_immutable BEFORE UPDATE OR DELETE ON imported_tls_certificates
 FOR EACH ROW EXECUTE FUNCTION immutable_xray_profile();

-- A held certificate is metadata only. No ACME process may replace its copied
-- source material until the node's single-writer adoption has been committed.
CREATE FUNCTION guard_imported_tls_certificate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM imported_tls_certificates WHERE certificate_id=OLD.id) THEN
  IF (NEW.id,NEW.node_id,NEW.tenant_id,NEW.domain,NEW.certificate_ref) IS DISTINCT FROM
     (OLD.id,OLD.node_id,OLD.tenant_id,OLD.domain,OLD.certificate_ref) THEN
   RAISE EXCEPTION 'imported certificate identity is immutable' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM node_xray_profiles p JOIN imported_tls_certificates t
   ON p.node_id=t.node_id AND p.import_id=t.import_id AND p.source_node_id=t.source_node_id
   WHERE t.certificate_id=NEW.id AND p.state='active') THEN
   IF NEW.auto_renew OR (NEW.fingerprint_sha256,NEW.issuer,NEW.not_before,NEW.not_after) IS DISTINCT FROM
      (OLD.fingerprint_sha256,OLD.issuer,OLD.not_before,OLD.not_after) THEN
    RAISE EXCEPTION 'imported certificate renewal is held' USING ERRCODE='23514';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER imported_tls_certificate_guard BEFORE UPDATE ON node_certificates
 FOR EACH ROW EXECUTE FUNCTION guard_imported_tls_certificate();
CREATE FUNCTION guard_imported_tls_job() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM imported_tls_certificates c WHERE c.certificate_id=NEW.certificate_id
  AND NOT EXISTS(SELECT 1 FROM node_xray_profiles p WHERE p.node_id=c.node_id AND p.import_id=c.import_id AND p.source_node_id=c.source_node_id AND p.state='active')) THEN
  RAISE EXCEPTION 'imported certificate renewal is held' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER imported_tls_job_guard BEFORE INSERT OR UPDATE OF certificate_id,node_id,tenant_id,status ON certificate_jobs
 FOR EACH ROW EXECUTE FUNCTION guard_imported_tls_job();

COMMIT;
