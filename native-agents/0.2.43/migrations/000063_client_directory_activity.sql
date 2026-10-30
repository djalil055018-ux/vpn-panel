BEGIN;

-- 61/62 are reserved by the separately reviewed migration-cutover candidate.
-- Explicitly apply this file by its ledger entry; a max(version) shortcut must
-- never treat earlier, unapplied migration files as installed.
ALTER TABLE node_client_traffic_cursors
 ADD COLUMN first_connected_at TIMESTAMPTZ,
 ADD COLUMN last_online_at TIMESTAMPTZ;
ALTER TABLE node_client_traffic_cursors ADD CONSTRAINT client_activity_timestamp_order
 CHECK (first_connected_at IS NULL OR last_online_at IS NULL OR first_connected_at<=last_online_at);

-- Existing observation times include reports with no active connection. They
-- cannot establish a first connection and are deliberately not backfilled.
CREATE INDEX node_client_traffic_last_online_idx
 ON node_client_traffic_cursors(client_id,last_online_at DESC) WHERE last_online_at IS NOT NULL;

COMMIT;
