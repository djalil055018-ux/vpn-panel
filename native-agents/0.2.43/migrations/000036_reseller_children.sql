BEGIN;
ALTER TABLE tenant_api_tokens DROP CONSTRAINT tenant_api_tokens_role_check;
ALTER TABLE tenant_api_tokens ADD CONSTRAINT tenant_api_tokens_role_check CHECK(role IN ('viewer','operator','reseller'));
ALTER TABLE tenant_api_tokens ADD COLUMN issued_by_token_id UUID REFERENCES tenant_api_tokens(id) ON DELETE CASCADE;
CREATE INDEX tenant_api_tokens_issuer_idx ON tenant_api_tokens(issued_by_token_id) WHERE issued_by_token_id IS NOT NULL;
CREATE TABLE reseller_children (
 child_tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 parent_tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK(child_tenant_id<>parent_tenant_id)
);
CREATE INDEX reseller_children_parent_idx ON reseller_children(parent_tenant_id);
COMMIT;
