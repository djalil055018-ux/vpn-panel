BEGIN;
CREATE TABLE webhook_dispatcher_runs (
 id BOOLEAN PRIMARY KEY DEFAULT true CHECK(id),
 last_success_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX webhook_deliveries_failed_idx ON webhook_deliveries(endpoint_id) WHERE status='failed';
COMMIT;
