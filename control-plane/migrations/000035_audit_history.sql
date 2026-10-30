CREATE INDEX IF NOT EXISTS audit_events_created_cursor_idx ON audit_events(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS audit_events_tenant_cursor_idx ON audit_events(tenant_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS audit_events_type_cursor_idx ON audit_events(event_type,created_at DESC,id DESC);
