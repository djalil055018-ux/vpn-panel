BEGIN;

ALTER TABLE remnawave_imports DROP CONSTRAINT remnawave_imports_state_check;
ALTER TABLE remnawave_imports ADD CONSTRAINT remnawave_imports_state_check
 CHECK(state IN ('held','activating','active','rollback_required'));

-- Starting a cutover freezes the reviewed import head. Existing preparation
-- APIs require state=held and cannot refresh credentials under an active node.
CREATE TABLE remnawave_cutovers (
 import_id UUID PRIMARY KEY,
 tenant_id UUID NOT NULL,
 request_sha256 TEXT NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
 inventory_sha256 TEXT NOT NULL,
 subscription_revision_id UUID NOT NULL,
 request JSONB NOT NULL CHECK(jsonb_typeof(request)='object' AND octet_length(request::text)<=131072),
 result JSONB NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=131072),
 state TEXT NOT NULL DEFAULT 'verifying' CHECK(state IN ('verifying','active','rollback_required')),
 started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 verified_at TIMESTAMPTZ,
 publication_sha256 TEXT CHECK(publication_sha256 ~ '^[0-9a-f]{64}$'),
 FOREIGN KEY(import_id,tenant_id) REFERENCES remnawave_imports(id,tenant_id),
 FOREIGN KEY(import_id,inventory_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256),
 FOREIGN KEY(subscription_revision_id) REFERENCES imported_subscription_revisions(id),
 CHECK(state<>'active' OR (verified_at IS NOT NULL AND publication_sha256 IS NOT NULL))
);
CREATE TRIGGER remnawave_cutover_identity_immutable
 BEFORE UPDATE OF import_id,tenant_id,request_sha256,inventory_sha256,subscription_revision_id,request,result
 ON remnawave_cutovers FOR EACH ROW EXECUTE FUNCTION immutable_xray_profile();

COMMIT;
