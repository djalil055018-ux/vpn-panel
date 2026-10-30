BEGIN;
CREATE TABLE node_traffic_delivery (
 node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 sample_sequence BIGINT NOT NULL CHECK(sample_sequence>0),
 recorded_at TIMESTAMPTZ NOT NULL,
 received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMIT;
