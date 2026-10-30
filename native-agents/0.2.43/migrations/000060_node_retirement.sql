-- Removing a node revokes its identity but retains deployments, traffic and audit.
CREATE TABLE node_retirements (
 node_id uuid PRIMARY KEY REFERENCES nodes(id),
 confirmed_name text NOT NULL,
 server_stopped boolean NOT NULL CHECK(server_stopped),
 retired_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION protect_node_retirement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'node retirement is immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER node_retirement_immutable BEFORE UPDATE OR DELETE ON node_retirements
 FOR EACH ROW EXECUTE FUNCTION protect_node_retirement();

-- A replacement may reuse the display name but always receives a new identity.
ALTER TABLE nodes DROP CONSTRAINT nodes_tenant_name_unique;
CREATE UNIQUE INDEX nodes_tenant_name_unique ON nodes(tenant_id,name) WHERE status<>'retired';

CREATE FUNCTION protect_retired_node() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status='retired' THEN
  RAISE EXCEPTION 'retired node is read only' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.status='retired' THEN
  IF NEW.agent_token_hash IS NOT NULL OR NEW.bootstrap_token_hash IS NOT NULL
   OR NOT EXISTS(SELECT 1 FROM node_retirements WHERE node_id=NEW.id)
   OR EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.id AND enabled)
   OR EXISTS(SELECT 1 FROM node_certificates WHERE node_id=NEW.id AND auto_renew)
  THEN RAISE EXCEPTION 'retirement prerequisites not satisfied' USING ERRCODE='23514'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retired_node_immutable BEFORE UPDATE OR DELETE ON nodes
 FOR EACH ROW EXECUTE FUNCTION protect_retired_node();

-- The parent lock closes the race with a request authenticated before revocation.
-- Existing history remains readable. None of these rows can restart a retired node.
CREATE FUNCTION reject_retired_node_work() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_status text;
BEGIN
 SELECT status INTO current_status FROM nodes WHERE id=NEW.node_id FOR SHARE;
 IF current_status='retired' THEN
  RAISE EXCEPTION 'retired node cannot accept work' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['desired_states','deployments','node_health',
  'deployment_execution_leases','recovery_attempts','rollout_plans','certificate_jobs',
  'node_certificates','vpn_services','agent_updaters','agent_fleet_jobs',
  'node_core_update_policies','execution_fence_requests'] LOOP
  EXECUTE format('CREATE TRIGGER reject_retired_work BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION reject_retired_node_work()',table_name);
 END LOOP;
END $$;
