-- An updater is independent of the Agent process it replaces.
CREATE FUNCTION agent_version_rank(v text) RETURNS bigint LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN v ~ '^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$'
 THEN split_part(v,'.',1)::bigint*100000000 + split_part(v,'.',2)::bigint*10000 + split_part(v,'.',3)::bigint END
$$;
CREATE TABLE agent_releases (
 version text PRIMARY KEY CHECK(agent_version_rank(version) IS NOT NULL),
 binary_sha256 text NOT NULL CHECK(binary_sha256 ~ '^[0-9a-f]{64}$'),
 installer_sha256 text NOT NULL CHECK(installer_sha256 ~ '^[0-9a-f]{64}$'),
 revoked boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION protect_agent_release_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.version<>OLD.version OR NEW.binary_sha256<>OLD.binary_sha256 OR NEW.installer_sha256<>OLD.installer_sha256 OR NEW.created_at<>OLD.created_at THEN
  RAISE EXCEPTION 'agent release identity is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER agent_release_identity BEFORE UPDATE ON agent_releases FOR EACH ROW EXECUTE FUNCTION protect_agent_release_identity();
INSERT INTO agent_releases(version,binary_sha256,installer_sha256) VALUES
 ('0.2.30','cdf069c64ca932480be5e80b89821253bc3304c44c1c2d94007d1bcab93477e2','6469e91d6d69b5ca7a90887df6dbaa068a6ae59756387d9b394b3dcbd135264a');
CREATE TABLE agent_fleet_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 auto_spread boolean NOT NULL DEFAULT true,
 target_version text REFERENCES agent_releases(version),
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO agent_fleet_policy(singleton) VALUES(true);
CREATE TABLE agent_fleet_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 request_key uuid UNIQUE NOT NULL DEFAULT gen_random_uuid(),
 target_version text NOT NULL REFERENCES agent_releases(version),
 origin_node_id uuid REFERENCES nodes(id) ON DELETE SET NULL,
 priority_node_id uuid REFERENCES nodes(id) ON DELETE SET NULL,
 origin text NOT NULL CHECK(origin IN ('manual','observed')),
 status text NOT NULL DEFAULT 'running' CHECK(status IN ('running','paused','completed')),
 message text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 completed_at timestamptz
);
CREATE UNIQUE INDEX agent_fleet_one_open ON agent_fleet_runs((true)) WHERE status IN ('running','paused');
CREATE TABLE agent_fleet_jobs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 run_id uuid NOT NULL REFERENCES agent_fleet_runs(id) ON DELETE CASCADE,
 node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 from_version text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','claimed','succeeded','failed','already_current','superseded')),
 claim_id uuid,
 claimed_at timestamptz,
 completed_at timestamptz,
 message text NOT NULL DEFAULT '' CHECK(length(message)<=256),
 binary_sha256 text,
 UNIQUE(run_id,node_id),
 CHECK((claim_id IS NULL)=(claimed_at IS NULL))
);
-- A crash never releases this slot by time alone. A late worker must report its
-- durable result; administrative resume cannot create overlapping installers.
CREATE UNIQUE INDEX agent_fleet_one_claim ON agent_fleet_jobs((true)) WHERE status='claimed';
CREATE TABLE agent_updaters (
 node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 version text NOT NULL,
 last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE agent_fleet_attempts (
 job_id uuid NOT NULL REFERENCES agent_fleet_jobs(id) ON DELETE CASCADE,
 claim_id uuid NOT NULL,
 result jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(job_id,claim_id)
);
-- The streamlined Xray action keeps the same rollout plan across POST retries.
ALTER TABLE rollout_plans ADD COLUMN request_key uuid UNIQUE;
