CREATE TABLE monitoring_incidents (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 rule TEXT NOT NULL,
 resource TEXT NOT NULL,
 resource_name TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
 observed_since TIMESTAMPTZ NOT NULL,
 last_observed_at TIMESTAMPTZ NOT NULL,
 opened_at TIMESTAMPTZ,
 resolved_at TIMESTAMPTZ,
 acknowledged_at TIMESTAMPTZ,
 CHECK(resolved_at IS NULL OR opened_at IS NOT NULL)
);
CREATE UNIQUE INDEX monitoring_active_condition_unique ON monitoring_incidents(rule,resource) WHERE resolved_at IS NULL;
CREATE INDEX monitoring_incidents_history_idx ON monitoring_incidents(opened_at DESC) WHERE opened_at IS NOT NULL;
CREATE TABLE monitoring_runs (
 id BOOLEAN PRIMARY KEY DEFAULT true CHECK(id),
 last_success_at TIMESTAMPTZ NOT NULL
);
