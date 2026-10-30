BEGIN;

CREATE TABLE vpn_client_limits (
    client_id UUID PRIMARY KEY REFERENCES vpn_clients(id) ON DELETE CASCADE,
    monthly_bytes BIGINT NOT NULL DEFAULT 0 CHECK(monthly_bytes BETWEEN 0 AND 9000000000000000),
    device_limit INTEGER NOT NULL DEFAULT 0 CHECK(device_limit BETWEEN 0 AND 1000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vpn_client_usage_monthly (
    client_id UUID NOT NULL REFERENCES vpn_clients(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    uplink_bytes BIGINT NOT NULL DEFAULT 0 CHECK(uplink_bytes BETWEEN 0 AND 9000000000000000),
    downlink_bytes BIGINT NOT NULL DEFAULT 0 CHECK(downlink_bytes BETWEEN 0 AND 9000000000000000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(client_id, period_start)
);

CREATE TABLE node_client_traffic_cursors (
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES vpn_clients(id) ON DELETE CASCADE,
    uplink_bytes BIGINT NOT NULL CHECK(uplink_bytes BETWEEN 0 AND 9000000000000000),
    downlink_bytes BIGINT NOT NULL CHECK(downlink_bytes BETWEEN 0 AND 9000000000000000),
    active_ips INTEGER NOT NULL CHECK(active_ips BETWEEN 0 AND 10000),
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(node_id, client_id)
);

CREATE INDEX node_client_traffic_cursors_observed_idx
ON node_client_traffic_cursors(observed_at);

COMMIT;
