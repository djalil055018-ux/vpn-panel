BEGIN;

-- A public label is independent of the service/runtime identity and imported
-- immutable source bundles. NULL retains the original generated/imported name.
ALTER TABLE vpn_services ADD COLUMN subscription_name TEXT
 CHECK (subscription_name IS NULL OR
  (char_length(btrim(subscription_name)) BETWEEN 1 AND 200
   AND subscription_name !~ '[[:cntrl:]]'));

COMMIT;
