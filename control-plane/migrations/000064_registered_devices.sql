BEGIN;

ALTER TABLE vpn_clients ADD COLUMN registered_device_limit INTEGER NOT NULL DEFAULT 0
 CHECK (registered_device_limit BETWEEN 0 AND 1000);

-- Keep the existing registry and bot API, extending it to clients without a bot account.
ALTER TABLE bot_devices ADD COLUMN id UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE bot_devices ADD COLUMN client_id UUID;
UPDATE bot_devices d SET client_id=b.client_id FROM bot_accounts b
 WHERE b.tenant_id=d.tenant_id AND b.legacy_id=d.legacy_id;
ALTER TABLE bot_devices DROP CONSTRAINT bot_devices_pkey;
ALTER TABLE bot_devices ADD PRIMARY KEY(id);
ALTER TABLE bot_devices ALTER COLUMN legacy_id DROP NOT NULL;
ALTER TABLE bot_devices ADD UNIQUE(tenant_id,legacy_id,hwid);
ALTER TABLE bot_devices ADD UNIQUE(client_id,hwid);
ALTER TABLE bot_devices ADD FOREIGN KEY(client_id,tenant_id)
 REFERENCES vpn_clients(id,tenant_id) ON DELETE CASCADE;
ALTER TABLE bot_devices ADD CHECK(client_id IS NOT NULL OR legacy_id IS NOT NULL);

-- Old bot code supplies tenant/numeric ID; new native code supplies tenant/client ID.
-- Both address exactly the same rows. Reject mismatched ownership on either path.
CREATE FUNCTION resolve_registered_device_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_client UUID; owner_legacy BIGINT;
BEGIN
 IF NEW.legacy_id IS NOT NULL THEN
  SELECT client_id INTO owner_client FROM bot_accounts
   WHERE tenant_id=NEW.tenant_id AND legacy_id=NEW.legacy_id;
  IF NOT FOUND OR (NEW.client_id IS NOT NULL AND NEW.client_id IS DISTINCT FROM owner_client) THEN
   RAISE EXCEPTION 'device owner mismatch' USING ERRCODE='23514';
  END IF;
  NEW.client_id=owner_client;
 ELSIF NEW.client_id IS NOT NULL THEN
  SELECT legacy_id INTO owner_legacy FROM bot_accounts
   WHERE tenant_id=NEW.tenant_id AND client_id=NEW.client_id AND deleted_at IS NULL;
  IF FOUND THEN NEW.legacy_id=owner_legacy; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER registered_device_owner BEFORE INSERT OR UPDATE OF tenant_id,legacy_id,client_id
 ON bot_devices FOR EACH ROW EXECUTE FUNCTION resolve_registered_device_owner();

COMMIT;
