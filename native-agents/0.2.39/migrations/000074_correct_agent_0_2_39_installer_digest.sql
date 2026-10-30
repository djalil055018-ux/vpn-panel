BEGIN;

CREATE OR REPLACE FUNCTION protect_agent_release_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Permit only this exact repair of the installer digest, and keep every
    -- other part of a published release identity immutable.
    IF OLD.version='0.2.39'
       AND OLD.binary_sha256='17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834'
       AND OLD.installer_sha256='a23842f04ba2058890f7ffea7a9a9490da1f6c032be40c4f6a8bbce5306cd758'
       AND NEW.version=OLD.version
       AND NEW.binary_sha256=OLD.binary_sha256
       AND NEW.installer_sha256='81fade30562dec32487c02b3bcb973681459e9d3414bed0a549e0bdf352d5238'
       AND NEW.created_at=OLD.created_at THEN
        RETURN NEW;
    END IF;
    IF NEW.version<>OLD.version OR NEW.binary_sha256<>OLD.binary_sha256
       OR NEW.installer_sha256<>OLD.installer_sha256 OR NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'agent release identity is immutable';
    END IF;
    RETURN NEW;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM nodes WHERE agent_version='0.2.39') THEN
        RAISE EXCEPTION 'refusing to repair agent 0.2.39 after a node has installed it';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM agent_fleet_jobs j
        JOIN agent_fleet_runs r ON r.id=j.run_id
        WHERE r.target_version='0.2.39' AND j.status='claimed'
    ) THEN
        RAISE EXCEPTION 'refusing to repair agent 0.2.39 while an update is claimed';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM agent_releases
        WHERE version='0.2.39'
          AND binary_sha256='17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834'
          AND installer_sha256='a23842f04ba2058890f7ffea7a9a9490da1f6c032be40c4f6a8bbce5306cd758'
          AND NOT revoked
    ) THEN
        RAISE EXCEPTION 'agent 0.2.39 release identity changed before repair';
    END IF;
END $$;

UPDATE agent_releases
SET installer_sha256='81fade30562dec32487c02b3bcb973681459e9d3414bed0a549e0bdf352d5238'
WHERE version='0.2.39'
  AND binary_sha256='17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834'
  AND installer_sha256='a23842f04ba2058890f7ffea7a9a9490da1f6c032be40c4f6a8bbce5306cd758'
  AND NOT revoked;

INSERT INTO audit_events(event_type,actor_type,actor_id,payload)
VALUES ('agent_release.installer_digest_corrected','system','migration',jsonb_build_object('version','0.2.39','reason','reviewed_tool_binary_digest_mismatch'));

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM agent_releases
        WHERE version='0.2.39'
          AND binary_sha256='17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834'
          AND installer_sha256='81fade30562dec32487c02b3bcb973681459e9d3414bed0a549e0bdf352d5238'
          AND NOT revoked
    ) THEN
        RAISE EXCEPTION 'agent 0.2.39 release digest correction failed';
    END IF;
END $$;

COMMIT;
