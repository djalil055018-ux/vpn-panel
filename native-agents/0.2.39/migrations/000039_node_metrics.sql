BEGIN;

CREATE TABLE node_metric_samples (
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    sample_bucket BIGINT NOT NULL,
    sampled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_percent DOUBLE PRECISION NOT NULL CHECK (cpu_percent >= 0 AND cpu_percent <= 100),
    load_1 DOUBLE PRECISION NOT NULL CHECK (load_1 >= 0),
    memory_total_bytes BIGINT NOT NULL CHECK (memory_total_bytes >= 0),
    memory_used_bytes BIGINT NOT NULL CHECK (memory_used_bytes >= 0 AND memory_used_bytes <= memory_total_bytes),
    disk_total_bytes BIGINT NOT NULL CHECK (disk_total_bytes >= 0),
    disk_used_bytes BIGINT NOT NULL CHECK (disk_used_bytes >= 0 AND disk_used_bytes <= disk_total_bytes),
    network_rx_bytes BIGINT NOT NULL CHECK (network_rx_bytes >= 0),
    network_tx_bytes BIGINT NOT NULL CHECK (network_tx_bytes >= 0),
    uptime_seconds BIGINT NOT NULL CHECK (uptime_seconds >= 0),
    PRIMARY KEY(node_id, sample_bucket)
);

CREATE INDEX node_metric_samples_time_idx
ON node_metric_samples(sampled_at DESC);

COMMIT;
