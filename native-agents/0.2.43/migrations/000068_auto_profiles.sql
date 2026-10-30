CREATE TABLE tenant_auto_profiles (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    name TEXT NOT NULL DEFAULT 'Авто' CHECK (char_length(name) BETWEEN 1 AND 80),
    russia_direct BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
