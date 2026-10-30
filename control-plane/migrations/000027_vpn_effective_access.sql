BEGIN;

CREATE VIEW vpn_effective_client_services AS

SELECT
    cs.tenant_id,
    cs.client_id,
    cs.service_id
FROM vpn_client_services cs

UNION

SELECT
    cap.tenant_id,
    cap.client_id,
    aps.service_id
FROM vpn_client_access_plans cap
JOIN vpn_access_plans ap
    ON ap.id = cap.plan_id
   AND ap.tenant_id = cap.tenant_id
JOIN vpn_access_plan_services aps
    ON aps.plan_id = cap.plan_id
   AND aps.tenant_id = cap.tenant_id
WHERE ap.enabled = true;

COMMIT;
