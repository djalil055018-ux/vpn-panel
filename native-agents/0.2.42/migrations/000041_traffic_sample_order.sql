BEGIN;
ALTER TABLE node_client_traffic_cursors
 ADD COLUMN counter_epoch TEXT NOT NULL DEFAULT '',
 ADD COLUMN sample_sequence BIGINT NOT NULL DEFAULT 0,
 ADD CONSTRAINT traffic_cursor_sample_metadata CHECK (
   (counter_epoch='' AND sample_sequence=0) OR
   (counter_epoch ~ '^[0-9a-f]{32}$' AND sample_sequence BETWEEN 1 AND 9000000000000000)
 );
COMMIT;
