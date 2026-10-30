ALTER TABLE node_health
ADD COLUMN last_known_good_core_version text,
ADD COLUMN snapshot_count bigint NOT NULL DEFAULT 0,
ADD COLUMN latest_snapshot_id text,
ADD COLUMN rollback_ready boolean NOT NULL DEFAULT false;

ALTER TABLE node_health
ADD CONSTRAINT node_health_snapshot_count_chk
CHECK (snapshot_count >= 0);
