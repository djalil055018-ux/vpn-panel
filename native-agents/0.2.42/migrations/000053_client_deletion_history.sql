BEGIN;

-- Preserve the original non-null invoice client identity for older readers.
-- Only the generated live reference participates in referential integrity;
-- ordinary inserts from old and new binaries still require an existing client.
ALTER TABLE billing_invoices ADD COLUMN deleted_client_id UUID;
ALTER TABLE billing_invoices ADD COLUMN live_client_id UUID GENERATED ALWAYS AS
 (CASE WHEN deleted_client_id IS NULL THEN client_id ELSE NULL END) STORED;
ALTER TABLE billing_invoices DROP CONSTRAINT billing_invoices_client_id_tenant_id_fkey;
ALTER TABLE billing_invoices ADD CONSTRAINT billing_invoice_live_client_fk
 FOREIGN KEY(live_client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id);
ALTER TABLE billing_invoices ADD CONSTRAINT billing_invoice_client_identity_chk
 CHECK (deleted_client_id IS NULL OR deleted_client_id=client_id);
ALTER TABLE billing_invoices ADD CONSTRAINT billing_deleted_client_not_pending_chk
 CHECK (deleted_client_id IS NULL OR status<>'pending');

ALTER TABLE remnawave_import_clients ALTER COLUMN client_id DROP NOT NULL;
ALTER TABLE remnawave_import_clients ADD COLUMN deleted_client_id UUID UNIQUE;
ALTER TABLE remnawave_import_clients ADD COLUMN deleted_client_name TEXT;
ALTER TABLE remnawave_import_clients ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE remnawave_import_clients ADD CONSTRAINT remnawave_client_identity_chk
 CHECK (
   (client_id IS NOT NULL AND deleted_client_id IS NULL AND deleted_client_name IS NULL AND deleted_at IS NULL)
   OR (client_id IS NULL AND deleted_client_id IS NOT NULL AND deleted_client_name IS NOT NULL AND deleted_at IS NOT NULL)
 );

COMMIT;
