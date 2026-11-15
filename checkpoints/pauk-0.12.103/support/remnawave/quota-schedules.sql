BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS pauk_remnawave_quota_schedules (
    client_id uuid PRIMARY KEY REFERENCES vpn_client_continuous_quotas(client_id) ON DELETE CASCADE,
    policy text NOT NULL CHECK (policy IN ('DAY','WEEK','MONTH','MONTH_ROLLING')),
    source_timezone text NOT NULL,
    source_created_at timestamptz NOT NULL,
    last_reset_at timestamptz,
    next_reset_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS pauk_remnawave_quota_due_idx ON pauk_remnawave_quota_schedules(next_reset_at,client_id);

CREATE OR REPLACE FUNCTION pauk_remnawave_next_reset(policy text, zone text, created_at timestamptz, after_at timestamptz)
RETURNS timestamptz LANGUAGE plpgsql STABLE SET search_path=public,pg_catalog AS $$
DECLARE
    local_after timestamp := after_at AT TIME ZONE zone;
    origin_day date := (created_at AT TIME ZONE 'UTC')::date;
    utc_month date := date_trunc('month', after_at AT TIME ZONE 'UTC')::date;
    first_due_day date := (origin_day+interval '1 month')::date;
    month_day date;
    anchor_day date;
    scheduled timestamp;
    candidate timestamptz;
BEGIN
    CASE policy
      WHEN 'DAY' THEN
        scheduled := date_trunc('day',local_after) + interval '5 minutes';
        IF scheduled AT TIME ZONE zone <= after_at THEN scheduled := scheduled+interval '1 day'; END IF;
      WHEN 'WEEK' THEN
        scheduled := date_trunc('week',local_after) + interval '15 minutes';
        IF scheduled AT TIME ZONE zone <= after_at THEN scheduled := scheduled+interval '7 days'; END IF;
      WHEN 'MONTH' THEN
        scheduled := date_trunc('month',local_after) + interval '20 minutes';
        IF scheduled AT TIME ZONE zone <= after_at THEN scheduled := scheduled+interval '1 month'; END IF;
      WHEN 'MONTH_ROLLING' THEN
        -- Remnawave selects the anniversary in its UTC database. Its scheduler
        -- checks for due clients each day at 00:10 in the scheduler's zone.
        utc_month := greatest(utc_month,date_trunc('month',first_due_day::timestamp)::date);
        FOR offset_month IN 0..2 LOOP
          month_day := (utc_month + make_interval(months=>offset_month))::date;
          anchor_day := month_day + (least(extract(day FROM origin_day)::integer,
              extract(day FROM month_day+interval '1 month - 1 day')::integer)-1);
          scheduled := date_trunc('day',(anchor_day::timestamp AT TIME ZONE 'UTC') AT TIME ZONE zone)+interval '10 minutes';
          candidate := scheduled AT TIME ZONE zone;
          IF (candidate AT TIME ZONE 'UTC')::date < anchor_day THEN
            candidate := (scheduled+interval '1 day') AT TIME ZONE zone;
          END IF;
          IF anchor_day >= first_due_day AND candidate > after_at AND
             (candidate AT TIME ZONE 'UTC')::date = anchor_day THEN
            RETURN candidate;
          END IF;
        END LOOP;
        RAISE EXCEPTION 'Unable to resolve rolling reset';
      ELSE RETURN NULL;
    END CASE;
    RETURN scheduled AT TIME ZONE zone;
END $$;

CREATE OR REPLACE FUNCTION pauk_remnawave_roll_quota(wanted uuid, through_at timestamptz)
RETURNS boolean LANGUAGE plpgsql SET search_path=public,pg_catalog AS $$
DECLARE
    schedule pauk_remnawave_quota_schedules%ROWTYPE;
    previous_upload bigint;
    previous_download bigint;
    cutoff timestamptz;
    following timestamptz;
BEGIN
    SELECT * INTO schedule
    FROM pauk_remnawave_quota_schedules
    WHERE client_id=wanted AND next_reset_at<=through_at FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;

    cutoff := schedule.next_reset_at;
    IF cutoff < through_at - interval '40 days' THEN
        cutoff := pauk_remnawave_next_reset(schedule.policy,schedule.source_timezone,schedule.source_created_at,through_at-interval '40 days');
    END IF;
    following := pauk_remnawave_next_reset(schedule.policy,schedule.source_timezone,schedule.source_created_at,cutoff);
    WHILE following <= through_at LOOP
        cutoff := following;
        following := pauk_remnawave_next_reset(schedule.policy,schedule.source_timezone,schedule.source_created_at,cutoff);
    END LOOP;

    SELECT uplink_bytes,downlink_bytes INTO STRICT previous_upload,previous_download
    FROM vpn_client_continuous_quotas WHERE client_id=wanted FOR UPDATE;
    UPDATE bot_accounts
    SET lifetime_offset_bytes=least(9000000000000000::bigint,lifetime_offset_bytes+previous_upload+previous_download),
        updated_at=now()
    WHERE client_id=wanted;
    -- Keep cumulative node counters so the next report cannot recharge this window.
    UPDATE vpn_client_continuous_quotas
    SET baseline_bytes=0,baseline_at=cutoff,uplink_bytes=0,downlink_bytes=0,updated_at=now()
    WHERE client_id=wanted;
    UPDATE pauk_remnawave_quota_schedules
    SET last_reset_at=cutoff,next_reset_at=following
    WHERE client_id=wanted;
    RETURN true;
END $$;

CREATE OR REPLACE FUNCTION pauk_remnawave_reset_due()
RETURNS integer LANGUAGE plpgsql SET search_path=public,pg_catalog AS $$
DECLARE
    boundary timestamptz := statement_timestamp();
    owner_id uuid;
    wanted uuid;
    reset_count integer := 0;
BEGIN
    FOR owner_id IN
        SELECT DISTINCT c.tenant_id
        FROM pauk_remnawave_quota_schedules s JOIN vpn_clients c ON c.id=s.client_id
        WHERE s.next_reset_at<=boundary ORDER BY c.tenant_id
    LOOP
      IF pg_try_advisory_xact_lock(1448103504,hashtext(owner_id::text)) THEN
        FOR wanted IN
            SELECT s.client_id FROM pauk_remnawave_quota_schedules s
            JOIN vpn_clients c ON c.id=s.client_id
            WHERE c.tenant_id=owner_id AND s.next_reset_at<=boundary
            ORDER BY s.next_reset_at,s.client_id LIMIT 5000
        LOOP
          IF pauk_remnawave_roll_quota(wanted,boundary) THEN reset_count := reset_count+1; END IF;
        END LOOP;
      END IF;
    END LOOP;
    RETURN reset_count;
END $$;

CREATE OR REPLACE FUNCTION pauk_remnawave_observe_traffic()
RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_catalog AS $$
BEGIN
    IF EXISTS (SELECT FROM pauk_remnawave_quota_schedules WHERE client_id=NEW.client_id) THEN
        PERFORM pauk_remnawave_roll_quota(NEW.client_id,least(NEW.observed_at,clock_timestamp()));
        PERFORM set_config('pauk.quota_client',NEW.client_id::text,true);
        PERFORM set_config('pauk.quota_observed_at',NEW.observed_at::text,true);
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS pauk_remnawave_observe_traffic ON node_client_traffic_cursors;
CREATE TRIGGER pauk_remnawave_observe_traffic AFTER INSERT OR UPDATE ON node_client_traffic_cursors
FOR EACH ROW EXECUTE FUNCTION pauk_remnawave_observe_traffic();

CREATE OR REPLACE FUNCTION pauk_remnawave_ignore_late_traffic()
RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_catalog AS $$
BEGIN
    IF (NEW.uplink_bytes>OLD.uplink_bytes OR NEW.downlink_bytes>OLD.downlink_bytes)
       AND current_setting('pauk.quota_client',true)=NEW.client_id::text
       AND nullif(current_setting('pauk.quota_observed_at',true),'')::timestamptz<OLD.baseline_at THEN
        UPDATE bot_accounts SET lifetime_offset_bytes=least(9000000000000000::bigint,
            lifetime_offset_bytes+NEW.uplink_bytes-OLD.uplink_bytes+NEW.downlink_bytes-OLD.downlink_bytes)
        WHERE client_id=NEW.client_id;
        NEW.uplink_bytes := OLD.uplink_bytes;
        NEW.downlink_bytes := OLD.downlink_bytes;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS pauk_remnawave_ignore_late_traffic ON vpn_client_continuous_quotas;
CREATE TRIGGER pauk_remnawave_ignore_late_traffic BEFORE UPDATE OF uplink_bytes,downlink_bytes
ON vpn_client_continuous_quotas FOR EACH ROW EXECUTE FUNCTION pauk_remnawave_ignore_late_traffic();

REVOKE ALL ON FUNCTION pauk_remnawave_roll_quota(uuid,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION pauk_remnawave_reset_due() FROM PUBLIC;
COMMIT;
