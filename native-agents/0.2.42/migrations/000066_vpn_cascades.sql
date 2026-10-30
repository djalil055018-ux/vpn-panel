BEGIN;

CREATE TABLE vpn_cascades (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 name TEXT NOT NULL CHECK(length(btrim(name)) BETWEEN 1 AND 128),
 plan_id UUID NOT NULL,
 entry_service_id UUID NOT NULL,
 exit_service_id UUID NOT NULL,
 entry_node_id UUID NOT NULL,
 exit_node_id UUID NOT NULL,
 entry_port INTEGER NOT NULL CHECK(entry_port BETWEEN 1 AND 65535 AND entry_port<>10085),
 enabled BOOLEAN NOT NULL DEFAULT false,
 transit_uuid UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(id,tenant_id),
 UNIQUE(entry_node_id,entry_port),
 CHECK(entry_node_id<>exit_node_id),
 FOREIGN KEY(plan_id,tenant_id) REFERENCES vpn_access_plans(id,tenant_id) ON DELETE CASCADE,
 FOREIGN KEY(entry_service_id,tenant_id,entry_node_id) REFERENCES vpn_services(id,tenant_id,node_id),
 FOREIGN KEY(exit_service_id,tenant_id,exit_node_id) REFERENCES vpn_services(id,tenant_id,node_id)
);
CREATE INDEX vpn_cascades_plan_idx ON vpn_cascades(plan_id);
CREATE INDEX vpn_cascades_exit_idx ON vpn_cascades(exit_node_id);

-- A cascade is an additional profile, never an implicit direct-service grant.
CREATE VIEW vpn_active_cascades AS
 SELECT c.* FROM vpn_cascades c
 JOIN vpn_access_plans p ON p.id=c.plan_id AND p.tenant_id=c.tenant_id
 JOIN vpn_services a ON a.id=c.entry_service_id AND a.tenant_id=c.tenant_id AND a.node_id=c.entry_node_id
 JOIN vpn_services b ON b.id=c.exit_service_id AND b.tenant_id=c.tenant_id AND b.node_id=c.exit_node_id
 JOIN nodes an ON an.id=c.entry_node_id AND an.tenant_id=c.tenant_id
 JOIN nodes bn ON bn.id=c.exit_node_id AND bn.tenant_id=c.tenant_id
 WHERE c.enabled AND p.enabled AND a.enabled AND b.enabled
 AND an.status<>'retired' AND bn.status<>'retired';

CREATE VIEW vpn_effective_client_cascades AS
 WITH memberships AS (
  SELECT tenant_id,client_id,plan_id FROM vpn_client_access_plans
  UNION
  SELECT tenant_id,client_id,plan_id FROM billing_entitlements WHERE expires_at>now()
  UNION
  SELECT tenant_id,client_id,plan_id FROM vpn_bot_client_access_plans
 )
 SELECT k.tenant_id,c.id AS client_id,k.id AS cascade_id,k.entry_node_id
 FROM vpn_active_cascades k JOIN memberships m ON m.tenant_id=k.tenant_id AND m.plan_id=k.plan_id
 JOIN vpn_clients c ON c.id=m.client_id AND c.tenant_id=m.tenant_id
 WHERE c.status='active' AND NOT c.remnawave_hold
 AND (c.expires_at IS NULL OR c.expires_at>now()) AND NOT vpn_client_quota_exceeded(c.id);

-- Include stale desired grants after a group change or client deletion.
CREATE FUNCTION vpn_node_cascade_client(node UUID,client UUID,credential TEXT)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM vpn_effective_client_cascades e WHERE e.entry_node_id=node AND e.client_id=client)
 OR EXISTS(SELECT 1 FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,
 jsonb_array_elements(COALESCE(ds.document->'xray_cascades'->'entries','[]'::jsonb)) e,
 jsonb_array_elements(COALESCE(e->'clients','[]'::jsonb)) u
 WHERE n.id=node AND (u->>'stats_key'=client::text OR u->>'id'=credential));
$$;
COMMIT;
