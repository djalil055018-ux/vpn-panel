BEGIN;

ALTER TABLE node_retirements
  DROP CONSTRAINT node_retirements_server_stopped_check;
ALTER TABLE node_retirements
  ADD COLUMN decommission_generation BIGINT;
ALTER TABLE node_retirements
  ADD CONSTRAINT node_retirements_safe_shutdown_check
  CHECK (server_stopped OR decommission_generation IS NOT NULL);

-- A decommission fence keeps the online agent alive long enough to apply the
-- service-free generation, while preventing any new listener or desired state.
CREATE OR REPLACE FUNCTION reject_retired_node_work() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_status text;
BEGIN
 SELECT status INTO current_status FROM nodes WHERE id=NEW.node_id FOR SHARE;
 IF current_status='retired' THEN
  RAISE EXCEPTION 'retired node cannot accept work' USING ERRCODE='23514';
 END IF;
 IF current_status='decommissioning' AND TG_TABLE_NAME IN (
   'desired_states','vpn_services','node_certificates','certificate_jobs',
   'agent_fleet_jobs','agent_updaters','node_core_update_policies',
   'execution_fence_requests','rollout_plans','recovery_attempts'
 ) THEN
  RAISE EXCEPTION 'decommissioning node cannot accept new work' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;

COMMIT;
