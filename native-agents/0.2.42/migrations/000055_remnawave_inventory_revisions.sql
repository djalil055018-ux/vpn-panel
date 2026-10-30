BEGIN;

-- The original staged inventory remains intact. Each reviewed held delta adds
-- immutable bytes and advances a separate current pointer in one transaction.
CREATE TABLE remnawave_inventory_revisions (
 import_id UUID NOT NULL REFERENCES remnawave_imports(id) ON DELETE CASCADE,
 inventory_sha256 TEXT NOT NULL CHECK(inventory_sha256 ~ '^[0-9a-f]{64}$'),
 parent_sha256 TEXT,
 sequence_id BIGSERIAL UNIQUE,
 inventory BYTEA NOT NULL CHECK(octet_length(inventory)<=67108864),
 report JSONB NOT NULL,
 captured_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(import_id,inventory_sha256),
 FOREIGN KEY(import_id,parent_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE remnawave_import_heads (
 import_id UUID PRIMARY KEY REFERENCES remnawave_imports(id) ON DELETE CASCADE,
 inventory_sha256 TEXT NOT NULL,
 FOREIGN KEY(import_id,inventory_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256) DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO remnawave_inventory_revisions(import_id,inventory_sha256,inventory,report,captured_at,created_at)
 SELECT id,inventory_sha256,inventory,report,captured_at,created_at FROM remnawave_imports;
INSERT INTO remnawave_import_heads SELECT id,inventory_sha256 FROM remnawave_imports;

CREATE FUNCTION remnawave_record_initial_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO remnawave_inventory_revisions(import_id,inventory_sha256,inventory,report,captured_at,created_at)
 VALUES(NEW.id,NEW.inventory_sha256,NEW.inventory,NEW.report,NEW.captured_at,NEW.created_at);
 INSERT INTO remnawave_import_heads VALUES(NEW.id,NEW.inventory_sha256);
 RETURN NEW;
END;
$$;
CREATE TRIGGER remnawave_initial_revision AFTER INSERT ON remnawave_imports
 FOR EACH ROW EXECUTE FUNCTION remnawave_record_initial_revision();

CREATE FUNCTION remnawave_reject_inventory_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Remnawave inventory history is immutable' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER remnawave_revision_immutable BEFORE UPDATE ON remnawave_inventory_revisions
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();
CREATE TRIGGER remnawave_original_immutable BEFORE UPDATE OF source_origin,inventory_sha256,inventory,report,user_count,captured_at ON remnawave_imports
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();

ALTER TABLE remnawave_import_clients ADD COLUMN source_present BOOLEAN NOT NULL DEFAULT true;
COMMIT;
