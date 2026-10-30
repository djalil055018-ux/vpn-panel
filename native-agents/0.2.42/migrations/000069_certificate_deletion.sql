BEGIN;

ALTER TABLE node_certificates
    DROP CONSTRAINT node_certificates_status_chk;

ALTER TABLE node_certificates
    ADD CONSTRAINT node_certificates_status_chk
    CHECK (status IN ('draft','pending','issuing','active','renewing','failed','revoked','deleting','deleted'));

ALTER TABLE certificate_jobs
    DROP CONSTRAINT certificate_jobs_operation_chk;

ALTER TABLE certificate_jobs
    ADD CONSTRAINT certificate_jobs_operation_chk
    CHECK (operation IN ('issue','renew','delete'));

DROP INDEX IF EXISTS node_certificates_node_domain_active_uidx;
CREATE UNIQUE INDEX node_certificates_node_domain_active_uidx
    ON node_certificates(node_id,domain)
    WHERE status NOT IN ('revoked','deleted');

COMMIT;
