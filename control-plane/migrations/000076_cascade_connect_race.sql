BEGIN;
ALTER TABLE vpn_cascades ADD COLUMN connect_race_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE vpn_cascades ADD COLUMN connect_race_attempts SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE vpn_cascades ADD COLUMN connect_race_clients BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vpn_cascades ADD CONSTRAINT vpn_cascade_client_dial_requires_policy CHECK (NOT connect_race_clients OR connect_race_attempts>0);
ALTER TABLE vpn_cascades ADD CONSTRAINT vpn_cascade_connect_race_bounded CHECK (
 (connect_race_ip='' AND connect_race_attempts=0) OR (connect_race_ip<>'' AND connect_race_attempts BETWEEN 2 AND 16)
);
CREATE INDEX vpn_cascade_client_dial_idx ON vpn_cascades(tenant_id,exit_node_id) WHERE connect_race_clients AND enabled AND connect_race_attempts>0;
-- The existing view intentionally contains a stored c.* expansion. Recreate
-- its exact predicate to append the two new public policy columns.
CREATE OR REPLACE VIEW vpn_active_cascades AS
 SELECT c.* FROM vpn_cascades c
 JOIN vpn_access_plans p ON p.id=c.plan_id AND p.tenant_id=c.tenant_id
 JOIN vpn_services a ON a.id=c.entry_service_id AND a.tenant_id=c.tenant_id AND a.node_id=c.entry_node_id
 JOIN vpn_services b ON b.id=c.exit_service_id AND b.tenant_id=c.tenant_id AND b.node_id=c.exit_node_id
 JOIN nodes an ON an.id=c.entry_node_id AND an.tenant_id=c.tenant_id
 JOIN nodes bn ON bn.id=c.exit_node_id AND bn.tenant_id=c.tenant_id
 WHERE c.enabled AND p.enabled AND a.enabled AND b.enabled
 AND an.status<>'retired' AND bn.status<>'retired';
COMMIT;
