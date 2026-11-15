import contextlib
import json
import os
import pwd
import re
import socket
import struct
import subprocess

DB = [
    "/usr/bin/docker", "exec", "-i", "vpn-platform-postgres", "sh", "-ec",
    'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"',
    "psql",
]
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
DIGEST = r"[0-9a-f]{64}"

SQL = """
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='11s';
SELECT set_config('pauk.migration', :'migration', true),
       set_config('pauk.plan', :'plan', true),
       set_config('pauk.digest', :'digest', true),
       set_config('pauk.actor', :'actor', true),
       set_config('pauk.timezone', :'timezone', true);
DO $migration$
#variable_conflict use_variable
DECLARE
    id uuid := current_setting('pauk.migration')::uuid;
    plan uuid := current_setting('pauk.plan')::uuid;
    reviewed text := current_setting('pauk.digest');
    actor text := current_setting('pauk.actor');
    source_zone text := current_setting('pauk.timezone');
    source text;
    tenant uuid;
    current_state text;
    inventory jsonb;
    snapshot_at timestamptz;
    customers integer;
    linked integer := 0;
    seed bigint;
BEGIN
    IF NOT EXISTS (SELECT FROM pg_timezone_names WHERE name=source_zone) THEN
        PERFORM set_config('pauk.result','invalid_timezone',true); RETURN;
    END IF;
    SELECT i.source_origin,i.tenant_id INTO source,tenant FROM remnawave_imports i WHERE i.id=id;
    IF NOT FOUND THEN
        PERFORM set_config('pauk.result','missing',true); RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(1448103509,hashtext(source));
    PERFORM pg_advisory_xact_lock(1448103504,hashtext(tenant::text));
    SELECT i.state,convert_from(r.inventory,'UTF8')::jsonb,r.captured_at
    INTO current_state,inventory,snapshot_at
    FROM remnawave_imports i
    JOIN remnawave_import_heads h ON h.import_id=i.id
    JOIN remnawave_inventory_revisions r ON r.import_id=i.id AND r.inventory_sha256=h.inventory_sha256
    WHERE i.id=id AND h.inventory_sha256=reviewed FOR UPDATE OF i,h;
    IF NOT FOUND OR current_state <> 'held' THEN
        PERFORM set_config('pauk.result','stale',true); RETURN;
    END IF;
    IF EXISTS (SELECT FROM remnawave_cutovers c WHERE c.import_id=id)
        OR EXISTS (SELECT FROM imported_subscription_profiles p WHERE p.import_id=id)
        OR EXISTS (SELECT FROM bot_profiles p WHERE p.import_id=id) THEN
        PERFORM set_config('pauk.result','legacy_prepared',true); RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT FROM vpn_access_plans p JOIN vpn_access_plan_services a ON a.plan_id=p.id AND a.tenant_id=p.tenant_id
        JOIN vpn_services s ON s.id=a.service_id AND s.tenant_id=a.tenant_id
        JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
        WHERE p.id=plan AND p.tenant_id=tenant AND p.enabled AND s.enabled
          AND n.status='online' AND n.applied_generation=n.desired_generation
          AND n.last_seen_at>now()-interval '3 minutes'
    ) THEN
        PERFORM set_config('pauk.result','plan_unavailable',true); RETURN;
    END IF;

    CREATE TEMP TABLE migration_clients ON COMMIT DROP AS
    SELECT u.*,m.client_id,c.status AS current_status,c.remnawave_hold,c.tenant_id,c.vless_uuid,
           c.expires_at,c.name,m.source_status, m.source_present,m.deleted_at
    FROM jsonb_to_recordset(inventory->'users') AS u(
        id bigint, username text, status text, "vlessUuid" uuid, "expireAt" timestamptz,
        "createdAt" timestamptz, "lastTrafficResetAt" timestamptz, "trafficLimitBytes" bigint, "trafficLimitStrategy" text,
        "hwidDeviceLimit" integer, "userTraffic" jsonb, "telegramId" bigint, email text, description text
    )
    LEFT JOIN remnawave_import_clients m ON m.import_id=id AND m.source_user_id=u.id
    LEFT JOIN vpn_clients c ON c.id=m.client_id;
    SELECT count(*) INTO customers FROM migration_clients;
    IF customers=0 OR EXISTS (
        SELECT FROM migration_clients x WHERE x.client_id IS NULL OR x.tenant_id<>tenant
           OR x.deleted_at IS NOT NULL OR x.source_present IS DISTINCT FROM true
           OR x.current_status<>'disabled' OR x.remnawave_hold IS DISTINCT FROM true
           OR x.name<>x.username OR x.source_status<>x.status OR x.vless_uuid<>"vlessUuid"
           OR x.expires_at IS DISTINCT FROM "expireAt"
    ) THEN
        PERFORM set_config('pauk.result','client_changed',true); RETURN;
    END IF;
    IF EXISTS (
        SELECT FROM migration_clients x
        WHERE (x."userTraffic"->>'usedTrafficBytes')::bigint NOT BETWEEN 0 AND 9000000000000000
           OR (x."userTraffic"->>'lifetimeUsedTrafficBytes')::bigint NOT BETWEEN 0 AND 9000000000000000
           OR x."trafficLimitBytes" NOT BETWEEN 0 AND 9000000000000000
           OR (x.status='LIMITED' AND (x."trafficLimitBytes"=0 OR (x."userTraffic"->>'usedTrafficBytes')::bigint<x."trafficLimitBytes"))
           OR (x.status='EXPIRED' AND x."expireAt">now())
           OR (x."lastTrafficResetAt">snapshot_at+interval '5 minutes')
           OR (x."hwidDeviceLimit" IS NOT NULL AND x."hwidDeviceLimit" NOT BETWEEN 0 AND 1000)
    ) THEN
        PERFORM set_config('pauk.result','invalid_policy',true); RETURN;
    END IF;
    IF EXISTS (
        SELECT FROM migration_clients x
        JOIN vpn_client_continuous_quotas q ON q.client_id=x.client_id
        WHERE q.limit_bytes<>x."trafficLimitBytes" OR q.baseline_bytes<>(x."userTraffic"->>'usedTrafficBytes')::bigint
           OR q.uplink_bytes<>0 OR q.downlink_bytes<>0
    ) OR EXISTS (
        SELECT FROM migration_clients x JOIN vpn_client_access_plans p ON p.client_id=x.client_id
    ) OR EXISTS (
        SELECT FROM migration_clients x JOIN vpn_client_services s ON s.client_id=x.client_id
    ) THEN
        PERFORM set_config('pauk.result','client_changed',true); RETURN;
    END IF;

    SELECT p.next_native_id INTO seed FROM bot_profiles p WHERE p.tenant_id=tenant AND p.state='active' FOR UPDATE;
    IF seed IS NULL AND EXISTS (SELECT FROM migration_clients WHERE coalesce("telegramId",0)>0 OR email IS NOT NULL OR description IS NOT NULL) THEN
        PERFORM set_config('pauk.result','bot_unavailable',true); RETURN;
    END IF;
    IF seed IS NOT NULL THEN
        IF EXISTS (
            SELECT FROM migration_clients x JOIN bot_accounts b ON b.tenant_id=tenant
            WHERE b.client_id=x.client_id OR b.username=x.username
               OR (x."telegramId">0 AND x."telegramId"=b.telegram_id AND b.source_present AND b.deleted_at IS NULL)
        ) THEN
            PERFORM set_config('pauk.result','identity_conflict',true); RETURN;
        END IF;
        INSERT INTO bot_accounts(tenant_id,legacy_id,client_id,username,telegram_id,email,description,
            hwid_device_limit,lifetime_offset_bytes,source_created_at,native_adopted)
        SELECT tenant,seed+row_number() OVER(ORDER BY x.id)-1,x.client_id,x.username,nullif(x."telegramId",0),x.email,x.description,
            x."hwidDeviceLimit",(x."userTraffic"->>'lifetimeUsedTrafficBytes')::bigint,x."createdAt",true
        FROM migration_clients x;
        GET DIAGNOSTICS linked = ROW_COUNT;
        INSERT INTO bot_subscription_aliases(alias,tenant_id,legacy_id)
        SELECT encode(gen_random_bytes(24),'hex'),tenant,b.legacy_id
        FROM bot_accounts b JOIN migration_clients x ON x.client_id=b.client_id;
        UPDATE bot_profiles p SET next_native_id=seed+linked WHERE p.tenant_id=tenant;
    END IF;

    INSERT INTO bot_devices(tenant_id,client_id,hwid,platform,os_version,device_model,created_at,updated_at)
    SELECT tenant,x.client_id,d.hwid,d.platform,d."osVersion",d."deviceModel",d."createdAt",d."updatedAt"
    FROM jsonb_to_recordset(inventory->'devices') d(
        "userId" bigint,hwid text,platform text,"osVersion" text,"deviceModel" text,"createdAt" timestamptz,"updatedAt" timestamptz
    ) JOIN migration_clients x ON x.id=d."userId";

    INSERT INTO vpn_client_continuous_quotas(client_id,limit_bytes,baseline_bytes,baseline_at)
    SELECT x.client_id,x."trafficLimitBytes",(x."userTraffic"->>'usedTrafficBytes')::bigint,snapshot_at
    FROM migration_clients x ON CONFLICT (client_id) DO NOTHING;
    INSERT INTO pauk_remnawave_quota_schedules(client_id,policy,source_timezone,source_created_at,last_reset_at,next_reset_at)
    SELECT x.client_id,x."trafficLimitStrategy",source_zone,x."createdAt",x."lastTrafficResetAt",
        pauk_remnawave_next_reset(x."trafficLimitStrategy",source_zone,x."createdAt",greatest(snapshot_at,x."lastTrafficResetAt"))
    FROM migration_clients x WHERE x."trafficLimitStrategy"<>'NO_RESET';

    INSERT INTO vpn_client_access_plans(tenant_id,client_id,plan_id)
    SELECT tenant,x.client_id,plan FROM migration_clients x;
    UPDATE vpn_clients c SET remnawave_hold=false,
        status=CASE WHEN x.status='DISABLED' THEN 'disabled' ELSE 'active' END,
        registered_device_limit=coalesce(x."hwidDeviceLimit",0),updated_at=now()
    FROM migration_clients x WHERE c.id=x.client_id;
    UPDATE remnawave_imports i SET state='active' WHERE i.id=id;
    INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload)
    VALUES(tenant,'remnawave.native_cutover','admin',actor,
        jsonb_build_object('import_id',id,'client_count',customers,'plan_id',plan,'inventory_sha256',reviewed,'bot_accounts',linked,'source_timezone',source_zone));
    PERFORM set_config('pauk.result','ok',true);
END
$migration$;
SELECT current_setting('pauk.result');
COMMIT;
"""

def activate(request):
    if not isinstance(request, dict) or set(request) != {"migration", "plan", "digest", "actor", "timezone"}:
        return "invalid"
    for key, pattern in (("migration", UUID), ("plan", UUID), ("actor", UUID), ("digest", DIGEST), ("timezone", r"[A-Za-z][A-Za-z0-9_+/-]{0,63}")):
        if not isinstance(request[key], str) or not re.fullmatch(pattern, request[key]):
            return "invalid"
    flags = [arg for key, value in request.items() for arg in ("-v", f"{key}={value}")]
    result = subprocess.run(DB + flags, input=SQL, text=True, capture_output=True, timeout=15)
    if result.returncode:
        import sys
        print("PAUK migration database error", result.stderr.splitlines()[0].split("DETAIL:")[0][:130], file=sys.stderr)
        return "failed"
    return result.stdout.strip().splitlines()[-1]

def main():
    with socket.socket(fileno=os.dup(0)) as connection:
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != pwd.getpwnam("vpnplatform-web").pw_uid:
            return
        connection.settimeout(3)
        with connection.makefile("rb") as request:
            payload = request.readline(1024)
        if len(payload) >= 1024 or not payload.endswith(b"\n"):
            status = "invalid"
        else:
            try:
                status = activate(json.loads(payload))
            except (UnicodeDecodeError, json.JSONDecodeError):
                status = "invalid"
            except (OSError, subprocess.TimeoutExpired, IndexError):
                status = "failed"
        connection.sendall(json.dumps({"status": status}).encode() + b"\n")

if __name__ == "__main__":
    with contextlib.suppress(ConnectionError, TimeoutError):
        main()
