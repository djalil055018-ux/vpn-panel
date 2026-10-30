BEGIN;

ALTER TABLE vpn_clients ADD COLUMN remnawave_hold BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vpn_clients ADD CONSTRAINT vpn_clients_remnawave_hold_chk
 CHECK (NOT remnawave_hold OR status='disabled');

CREATE TABLE remnawave_imports (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 source_origin TEXT NOT NULL UNIQUE,
 inventory_sha256 TEXT NOT NULL CHECK (inventory_sha256 ~ '^[0-9a-f]{64}$'),
 inventory BYTEA NOT NULL CHECK (octet_length(inventory)<=67108864),
 report JSONB NOT NULL,
 user_count INTEGER NOT NULL CHECK (user_count BETWEEN 0 AND 100000),
 state TEXT NOT NULL DEFAULT 'held' CHECK (state='held'),
 captured_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(id,tenant_id)
);

CREATE TABLE remnawave_import_clients (
 import_id UUID NOT NULL REFERENCES remnawave_imports(id) ON DELETE RESTRICT,
 source_user_id BIGINT NOT NULL CHECK (source_user_id>0),
 source_status TEXT NOT NULL CHECK (source_status IN ('ACTIVE','DISABLED','EXPIRED','LIMITED')),
 client_id UUID NOT NULL UNIQUE REFERENCES vpn_clients(id) ON DELETE RESTRICT,
 PRIMARY KEY(import_id,source_user_id)
);

-- Original credentials, subscriptions, traffic, HWID and all unmapped source
-- fields remain in the private inventory. No HTTP route returns inventory bytes.
-- Staging creates disabled clients; an explicit future cutover must release holds.
COMMIT;
