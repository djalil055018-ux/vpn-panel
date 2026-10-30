BEGIN;

INSERT INTO agent_releases(version,binary_sha256,installer_sha256)
VALUES (
    '0.2.39',
    '17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834',
    'a23842f04ba2058890f7ffea7a9a9490da1f6c032be40c4f6a8bbce5306cd758'
)
ON CONFLICT(version) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM agent_releases
        WHERE version='0.2.39'
          AND (binary_sha256<>'17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834'
            OR installer_sha256<>'a23842f04ba2058890f7ffea7a9a9490da1f6c032be40c4f6a8bbce5306cd758'
            OR revoked)
    ) THEN
        RAISE EXCEPTION 'agent release 0.2.39 already exists with a different identity';
    END IF;
END $$;

COMMIT;
