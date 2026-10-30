BEGIN;
-- Existing Xray agents supply a measured count and omit the availability flag.
-- Keep integer cursors compatible with older readers while preserving unknown
-- telemetry explicitly for cores which cannot measure distinct addresses.
ALTER TABLE node_client_traffic_cursors
 ADD COLUMN active_ips_known BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE node_client_traffic_cursors
 ADD CONSTRAINT traffic_unknown_address_count CHECK(active_ips_known OR active_ips=0);
COMMIT;
