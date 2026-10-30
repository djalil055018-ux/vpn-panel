BEGIN;
CREATE TABLE node_backup_reports (
    node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    document JSONB NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMIT;
