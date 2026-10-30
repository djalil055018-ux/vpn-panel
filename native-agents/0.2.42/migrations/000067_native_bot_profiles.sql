BEGIN;

-- A fresh installation has no legacy inventory or cutover. Keep that explicit;
-- imported profiles retain every existing identity/readiness requirement.
ALTER TABLE bot_profiles ADD COLUMN profile_kind TEXT NOT NULL DEFAULT 'imported'
 CHECK(profile_kind IN ('imported','native'));
ALTER TABLE bot_profiles ALTER COLUMN import_id DROP NOT NULL;
ALTER TABLE bot_profiles ALTER COLUMN inventory_sha256 DROP NOT NULL;
ALTER TABLE bot_profiles ADD CONSTRAINT bot_profile_origin CHECK(
 (profile_kind='imported' AND import_id IS NOT NULL AND inventory_sha256 IS NOT NULL)
 OR (profile_kind='native' AND import_id IS NULL AND inventory_sha256 IS NULL));

CREATE FUNCTION enforce_bot_profile_origin() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.profile_kind,NEW.import_id) IS DISTINCT FROM (OLD.profile_kind,OLD.import_id) THEN
  RAISE EXCEPTION 'Bot profile origin is immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER bot_profile_origin_immutable BEFORE UPDATE OF profile_kind,import_id
 ON bot_profiles FOR EACH ROW EXECUTE FUNCTION enforce_bot_profile_origin();

COMMIT;
