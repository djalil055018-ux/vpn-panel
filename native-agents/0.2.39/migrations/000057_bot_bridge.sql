BEGIN;

-- A prepared bridge is unavailable to the bot until the separately reviewed
-- runtime/subscription cutover. The inventory digest remains an exact byte hash.
CREATE TABLE bot_profiles (
 tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
 import_id UUID NOT NULL UNIQUE,
 inventory_sha256 TEXT NOT NULL,
 subscription_base TEXT NOT NULL CHECK(length(subscription_base) BETWEEN 9 AND 4096),
 state TEXT NOT NULL DEFAULT 'held' CHECK(state IN ('held','active','paused')),
 source_identity_reviewed BOOLEAN NOT NULL DEFAULT false,
 next_native_id BIGINT NOT NULL DEFAULT 4503599627370496
  CHECK(next_native_id BETWEEN 4503599627370496 AND 9007199254740992),
 prepared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 activated_at TIMESTAMPTZ,
 FOREIGN KEY(import_id,tenant_id) REFERENCES remnawave_imports(id,tenant_id),
 FOREIGN KEY(import_id,inventory_sha256) REFERENCES remnawave_inventory_revisions(import_id,inventory_sha256),
 CHECK(state<>'active' OR (activated_at IS NOT NULL AND source_identity_reviewed))
);

CREATE TABLE bot_accounts (
 tenant_id UUID NOT NULL REFERENCES bot_profiles(tenant_id),
 legacy_id BIGINT NOT NULL CHECK(legacy_id BETWEEN 1 AND 9007199254740991),
 client_id UUID UNIQUE,
 username TEXT NOT NULL CHECK(octet_length(username) BETWEEN 1 AND 256),
 telegram_id BIGINT CHECK(telegram_id BETWEEN 0 AND 9007199254740991),
 email TEXT CHECK(octet_length(email)<=320),
 description TEXT CHECK(octet_length(description)<=4096),
 hwid_device_limit INTEGER CHECK(hwid_device_limit BETWEEN 0 AND 1000),
 lifetime_offset_bytes BIGINT NOT NULL CHECK(lifetime_offset_bytes BETWEEN 0 AND 9000000000000000),
 source_created_at TIMESTAMPTZ NOT NULL,
 source_present BOOLEAN NOT NULL DEFAULT true,
 deleted_client_id UUID,
 deleted_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,legacy_id),
 UNIQUE(tenant_id,username),
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id) ON DELETE RESTRICT,
 CHECK((client_id IS NOT NULL AND deleted_at IS NULL AND deleted_client_id IS NULL)
    OR (client_id IS NULL AND deleted_at IS NOT NULL AND deleted_client_id IS NOT NULL))
);
CREATE INDEX bot_accounts_telegram ON bot_accounts(tenant_id,telegram_id,legacy_id) WHERE deleted_at IS NULL;
CREATE INDEX bot_accounts_email ON bot_accounts(tenant_id,email,legacy_id) WHERE deleted_at IS NULL;

CREATE TABLE bot_squads (
 tenant_id UUID NOT NULL REFERENCES bot_profiles(tenant_id),
 source_uuid UUID NOT NULL,
 name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 256),
 plan_id UUID,
 source_present BOOLEAN NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,source_uuid),
 UNIQUE(plan_id),
 FOREIGN KEY(plan_id,tenant_id) REFERENCES vpn_access_plans(id,tenant_id) ON DELETE RESTRICT
);
CREATE TABLE bot_account_squads (
 tenant_id UUID NOT NULL,
 legacy_id BIGINT NOT NULL,
 source_uuid UUID NOT NULL,
 PRIMARY KEY(tenant_id,legacy_id,source_uuid),
 FOREIGN KEY(tenant_id,legacy_id) REFERENCES bot_accounts(tenant_id,legacy_id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,source_uuid) REFERENCES bot_squads(tenant_id,source_uuid)
);
CREATE TABLE bot_devices (
 tenant_id UUID NOT NULL,
 legacy_id BIGINT NOT NULL,
 hwid TEXT NOT NULL CHECK(octet_length(hwid) BETWEEN 1 AND 512),
 platform TEXT CHECK(octet_length(platform)<=2048),
 os_version TEXT CHECK(octet_length(os_version)<=2048),
 device_model TEXT CHECK(octet_length(device_model)<=2048),
 created_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(tenant_id,legacy_id,hwid),
 FOREIGN KEY(tenant_id,legacy_id) REFERENCES bot_accounts(tenant_id,legacy_id) ON DELETE CASCADE
);
CREATE TABLE bot_subscription_aliases (
 alias TEXT PRIMARY KEY CHECK(alias ~ '^[A-Za-z0-9_-]{16,128}$'),
 tenant_id UUID NOT NULL,
 legacy_id BIGINT NOT NULL,
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 revoked_at TIMESTAMPTZ,
 FOREIGN KEY(tenant_id,legacy_id) REFERENCES bot_accounts(tenant_id,legacy_id),
 CHECK((state='active' AND revoked_at IS NULL) OR (state='revoked' AND revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX bot_subscription_one_active ON bot_subscription_aliases(tenant_id,legacy_id) WHERE state='active';

-- No pending receipt is visible: the response and effect commit together.
-- Keep receipts and numeric tombstones so retries cannot resurrect deleted users.
CREATE TABLE bot_operations (
 tenant_id UUID NOT NULL REFERENCES bot_profiles(tenant_id),
 operation_key TEXT NOT NULL CHECK(operation_key ~ '^[0-9a-f]{64}$'),
 fingerprint TEXT NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 status_code INTEGER NOT NULL CHECK(status_code IN (200,201,204)),
 response JSONB NOT NULL CHECK(octet_length(response::text)<=262144),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,operation_key)
);

-- Every deletion path, including the existing native administrator UI, must
-- preserve the numeric identity while revoking public aliases and live metadata.
CREATE FUNCTION bot_client_deleted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE bot_subscription_aliases a SET state='revoked',revoked_at=COALESCE(revoked_at,now())
  FROM bot_accounts b WHERE b.client_id=OLD.id AND a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id;
 DELETE FROM bot_devices d USING bot_accounts b
  WHERE b.client_id=OLD.id AND d.tenant_id=b.tenant_id AND d.legacy_id=b.legacy_id;
 DELETE FROM bot_account_squads s USING bot_accounts b
  WHERE b.client_id=OLD.id AND s.tenant_id=b.tenant_id AND s.legacy_id=b.legacy_id;
 UPDATE bot_accounts SET deleted_client_id=OLD.id,client_id=NULL,deleted_at=now(),updated_at=now(),
  telegram_id=NULL,email=NULL,description=NULL WHERE client_id=OLD.id;
 RETURN OLD;
END;
$$;
CREATE TRIGGER bot_client_deletion BEFORE DELETE ON vpn_clients
 FOR EACH ROW EXECUTE FUNCTION bot_client_deleted();

-- Bot memberships are a separate source of access. Clearing source squads must
-- not delete grants independently assigned by a native administrator or billing.
-- Pausing the bot API does not disconnect existing VPN clients.
CREATE VIEW vpn_bot_client_access_plans AS
 SELECT DISTINCT b.tenant_id,b.client_id,s.plan_id
 FROM bot_accounts b JOIN bot_profiles p ON p.tenant_id=b.tenant_id
 JOIN bot_account_squads m ON m.tenant_id=b.tenant_id AND m.legacy_id=b.legacy_id
 JOIN bot_squads s ON s.tenant_id=m.tenant_id AND s.source_uuid=m.source_uuid
 WHERE b.client_id IS NOT NULL AND b.deleted_at IS NULL AND b.source_present
 AND p.activated_at IS NOT NULL AND p.state IN ('active','paused')
 AND s.source_present AND s.plan_id IS NOT NULL;
CREATE OR REPLACE VIEW vpn_effective_client_services AS
 SELECT tenant_id,client_id,service_id FROM vpn_client_services
 UNION
 SELECT cap.tenant_id,cap.client_id,aps.service_id
 FROM vpn_client_access_plans cap
 JOIN vpn_access_plans ap ON ap.id=cap.plan_id AND ap.tenant_id=cap.tenant_id
 JOIN vpn_access_plan_services aps ON aps.plan_id=cap.plan_id AND aps.tenant_id=cap.tenant_id
 WHERE ap.enabled
 UNION
 SELECT be.tenant_id,be.client_id,aps.service_id
 FROM billing_entitlements be
 JOIN vpn_access_plans ap ON ap.id=be.plan_id AND ap.tenant_id=be.tenant_id
 JOIN vpn_access_plan_services aps ON aps.plan_id=be.plan_id AND aps.tenant_id=be.tenant_id
 WHERE ap.enabled AND be.expires_at>now()
 UNION
 SELECT cap.tenant_id,cap.client_id,aps.service_id
 FROM vpn_bot_client_access_plans cap
 JOIN vpn_access_plans ap ON ap.id=cap.plan_id AND ap.tenant_id=cap.tenant_id
 JOIN vpn_access_plan_services aps ON aps.plan_id=cap.plan_id AND aps.tenant_id=cap.tenant_id
 WHERE ap.enabled;
COMMIT;
