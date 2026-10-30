BEGIN;

CREATE TABLE remnawave_subscription_settings (
 import_id UUID NOT NULL REFERENCES remnawave_imports(id) ON DELETE RESTRICT,
 settings_sha256 TEXT NOT NULL CHECK(settings_sha256 ~ '^[0-9a-f]{64}$'),
 source BYTEA NOT NULL CHECK(octet_length(source) BETWEEN 1 AND 16777216),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(import_id,settings_sha256),
 CHECK(encode(sha256(source),'hex')=settings_sha256)
);
CREATE TRIGGER imported_settings_immutable BEFORE UPDATE OR DELETE ON remnawave_subscription_settings
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();

CREATE TABLE imported_subscription_revisions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL,
 import_id UUID NOT NULL,
 inventory_sha256 TEXT NOT NULL,
 settings_sha256 TEXT NOT NULL,
 bundle_sha256 TEXT NOT NULL CHECK(bundle_sha256 ~ '^[0-9a-f]{64}$'),
 bundle BYTEA NOT NULL CHECK(octet_length(bundle) BETWEEN 1 AND 8388608),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK(encode(sha256(bundle),'hex')=bundle_sha256),
 UNIQUE(id,tenant_id),
 UNIQUE(id,tenant_id,import_id),
 UNIQUE(import_id,inventory_sha256,settings_sha256),
 FOREIGN KEY(import_id,tenant_id) REFERENCES remnawave_imports(id,tenant_id),
 FOREIGN KEY(import_id,inventory_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256),
 FOREIGN KEY(import_id,settings_sha256) REFERENCES remnawave_subscription_settings(import_id,settings_sha256)
);
CREATE TRIGGER imported_subscription_revision_immutable BEFORE UPDATE OR DELETE ON imported_subscription_revisions
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();

CREATE TABLE imported_subscription_profiles (
 tenant_id UUID PRIMARY KEY REFERENCES bot_profiles(tenant_id),
 import_id UUID NOT NULL UNIQUE,
 revision_id UUID NOT NULL,
 state TEXT NOT NULL DEFAULT 'prepared' CHECK(state IN ('prepared','active','paused')),
 activation_sha256 TEXT CHECK(activation_sha256 ~ '^[0-9a-f]{64}$'),
 prepared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 activated_at TIMESTAMPTZ,
 FOREIGN KEY(revision_id,tenant_id,import_id) REFERENCES imported_subscription_revisions(id,tenant_id,import_id),
 CHECK(state='prepared' OR (activation_sha256 IS NOT NULL AND activated_at IS NOT NULL)),
 CHECK(state<>'prepared' OR (activation_sha256 IS NULL AND activated_at IS NULL))
);
CREATE FUNCTION enforce_imported_subscription_head() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.tenant_id,NEW.import_id) IS DISTINCT FROM (OLD.tenant_id,OLD.import_id)
    OR (OLD.state<>'prepared' AND (NEW.state='prepared' OR NEW.revision_id<>OLD.revision_id)) THEN
  RAISE EXCEPTION 'active imported subscription identity cannot be rewritten' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER imported_subscription_head_identity BEFORE UPDATE ON imported_subscription_profiles
 FOR EACH ROW EXECUTE FUNCTION enforce_imported_subscription_head();

-- Native service FKs prevent dangling or cross-tenant public host grants.
CREATE TABLE imported_subscription_host_services (
 revision_id UUID NOT NULL,
 tenant_id UUID NOT NULL,
 source_host_id UUID NOT NULL,
 service_id UUID NOT NULL,
 PRIMARY KEY(revision_id,source_host_id,service_id),
 FOREIGN KEY(revision_id,tenant_id) REFERENCES imported_subscription_revisions(id,tenant_id),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id)
);
CREATE TABLE imported_subscription_squad_services (
 revision_id UUID NOT NULL,
 tenant_id UUID NOT NULL,
 source_squad_id UUID NOT NULL,
 service_id UUID NOT NULL,
 PRIMARY KEY(revision_id,source_squad_id,service_id),
 FOREIGN KEY(revision_id,tenant_id) REFERENCES imported_subscription_revisions(id,tenant_id),
 FOREIGN KEY(tenant_id,source_squad_id) REFERENCES bot_squads(tenant_id,source_uuid),
 FOREIGN KEY(service_id,tenant_id) REFERENCES vpn_services(id,tenant_id)
);
CREATE TABLE imported_subscription_external_accounts (
 revision_id UUID NOT NULL,
 tenant_id UUID NOT NULL,
 legacy_id BIGINT NOT NULL,
 source_external_id UUID NOT NULL,
 PRIMARY KEY(revision_id,legacy_id),
 FOREIGN KEY(revision_id,tenant_id) REFERENCES imported_subscription_revisions(id,tenant_id),
 FOREIGN KEY(tenant_id,legacy_id) REFERENCES bot_accounts(tenant_id,legacy_id)
);
CREATE TRIGGER imported_subscription_host_immutable BEFORE UPDATE OR DELETE ON imported_subscription_host_services
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();
CREATE TRIGGER imported_subscription_squad_immutable BEFORE UPDATE OR DELETE ON imported_subscription_squad_services
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();
CREATE TRIGGER imported_subscription_external_immutable BEFORE UPDATE OR DELETE ON imported_subscription_external_accounts
 FOR EACH ROW EXECUTE FUNCTION remnawave_reject_inventory_update();
COMMIT;
