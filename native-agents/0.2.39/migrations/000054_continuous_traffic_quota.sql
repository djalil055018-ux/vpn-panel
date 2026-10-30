BEGIN;

-- Imported total traffic has no directional breakdown. Keep it distinct from
-- uplink/downlink measured by target nodes; calendar rollover cannot reset it.
CREATE TABLE vpn_client_continuous_quotas (
 client_id UUID PRIMARY KEY REFERENCES vpn_clients(id) ON DELETE CASCADE,
 limit_bytes BIGINT NOT NULL CHECK (limit_bytes BETWEEN 0 AND 9000000000000000),
 baseline_bytes BIGINT NOT NULL CHECK (baseline_bytes BETWEEN 0 AND 9000000000000000),
 baseline_at TIMESTAMPTZ NOT NULL,
 uplink_bytes BIGINT NOT NULL DEFAULT 0 CHECK (uplink_bytes BETWEEN 0 AND 9000000000000000),
 downlink_bytes BIGINT NOT NULL DEFAULT 0 CHECK (downlink_bytes BETWEEN 0 AND 9000000000000000),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Presence of a continuous policy overrides the monthly policy even when its
-- limit is zero (unlimited). All CP access paths use this same predicate.
CREATE FUNCTION vpn_client_quota_exceeded(wanted UUID) RETURNS BOOLEAN
 LANGUAGE SQL STABLE AS $$
 SELECT COALESCE(
   (SELECT q.limit_bytes>0 AND q.baseline_bytes+q.uplink_bytes+q.downlink_bytes>=q.limit_bytes
    FROM vpn_client_continuous_quotas q WHERE q.client_id=wanted),
   (SELECT l.monthly_bytes>0 AND COALESCE(u.uplink_bytes+u.downlink_bytes,0)>=l.monthly_bytes
    FROM vpn_client_limits l LEFT JOIN vpn_client_usage_monthly u
     ON u.client_id=l.client_id AND u.period_start=date_trunc('month',now() AT TIME ZONE 'UTC')::date
    WHERE l.client_id=wanted),false)
$$;

COMMIT;
