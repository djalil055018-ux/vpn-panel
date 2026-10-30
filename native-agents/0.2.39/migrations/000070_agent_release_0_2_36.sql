BEGIN;

INSERT INTO agent_releases(version,binary_sha256,installer_sha256)
VALUES (
    '0.2.36',
    'a985c71cbf8136236fe81df858cbceef8b25a396aa3dcffd9b2b2d4b6c7c67e4',
    '4a2765b2fd5ff5c2ece65bc39f26995ee65a5cdbd199bc48590b5bea8e6313bd'
)
ON CONFLICT (version) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_releases
        WHERE version = '0.2.36'
          AND (
              binary_sha256 <> 'a985c71cbf8136236fe81df858cbceef8b25a396aa3dcffd9b2b2d4b6c7c67e4'
              OR installer_sha256 <> '4a2765b2fd5ff5c2ece65bc39f26995ee65a5cdbd199bc48590b5bea8e6313bd'
              OR revoked
          )
    ) THEN
        RAISE EXCEPTION 'agent release 0.2.36 already exists with a different identity';
    END IF;
END $$;

COMMIT;
