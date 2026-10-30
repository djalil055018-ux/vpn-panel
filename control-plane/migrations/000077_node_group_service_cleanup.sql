BEGIN;
-- Group membership is live configuration; service/node history remains intact.
-- Run inside the same transaction as either phase of node removal.
CREATE FUNCTION detach_removed_node_group_services() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status IN ('decommissioning','retired') AND OLD.status IS DISTINCT FROM NEW.status THEN
  WITH removed AS (
   DELETE FROM vpn_access_plan_services ps USING vpn_services s
   WHERE ps.service_id=s.id AND ps.tenant_id=s.tenant_id AND s.node_id=NEW.id
   RETURNING ps.tenant_id,ps.plan_id
  )
  INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,payload)
  SELECT tenant_id,NEW.id,'access_plan.node_services_removed','system',
   jsonb_build_object('plan_id',plan_id,'removed_service_count',count(*),'node_status',NEW.status)
  FROM removed GROUP BY tenant_id,plan_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER node_group_services_removed AFTER UPDATE OF status ON nodes
 FOR EACH ROW EXECUTE FUNCTION detach_removed_node_group_services();

-- Serialize membership admission with the node's retirement lock. Even an old
-- application or direct import cannot reintroduce an unavailable service.
CREATE FUNCTION reject_removed_node_group_service() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE node_status text;
BEGIN
 SELECT n.status INTO node_status FROM vpn_services s JOIN nodes n ON n.id=s.node_id
 WHERE s.id=NEW.service_id AND s.tenant_id=NEW.tenant_id FOR SHARE OF n;
 IF node_status IN ('decommissioning','retired') THEN
  RAISE EXCEPTION 'removed node service cannot belong to an access plan' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER access_plan_service_node_admission BEFORE INSERT OR UPDATE ON vpn_access_plan_services
 FOR EACH ROW EXECUTE FUNCTION reject_removed_node_group_service();

-- Repair historical references without changing clients, working services,
-- archived service records, cascades, or any retired-node execution history.
WITH removed AS (
 DELETE FROM vpn_access_plan_services ps USING vpn_services s,nodes n
 WHERE ps.service_id=s.id AND ps.tenant_id=s.tenant_id AND s.node_id=n.id
  AND n.status IN ('decommissioning','retired')
 RETURNING ps.tenant_id,ps.plan_id,s.node_id
)
INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,payload)
SELECT tenant_id,node_id,'access_plan.node_services_removed','system',
 jsonb_build_object('plan_id',plan_id,'removed_service_count',count(*),'historical_cleanup',true)
FROM removed GROUP BY tenant_id,node_id,plan_id;
COMMIT;
