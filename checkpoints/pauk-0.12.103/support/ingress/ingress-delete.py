import contextlib
import ipaddress
import json
import os
import pwd
import re
import socket
import struct
import subprocess
import sys

DATABASE = [
    "/usr/bin/docker", "exec", "-i", "vpn-platform-postgres", "sh", "-ec",
    'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"',
    "psql",
]

ENABLED_ADDRESSES = """
SELECT coalesce(jsonb_agg(DISTINCT lower(public_address) ORDER BY lower(public_address)), '[]')
FROM vpn_services
WHERE enabled AND public_address <> ''
"""

READ = f"""
SELECT jsonb_build_object(
    'revision', revision, 'config', config, 'services', ({ENABLED_ADDRESSES})
) FROM platform_ingress_config WHERE singleton;
"""

DELETE = f"""
BEGIN;
SET LOCAL lock_timeout = '1500ms';
SET LOCAL statement_timeout = '3000ms';
LOCK TABLE ingress_provision_runs, vpn_services IN SHARE MODE;
SELECT set_config('pauk.entry_id', :'entry_id', true),
       set_config('pauk.expected_revision', :'revision', true),
       set_config('pauk.expected_address', :'address', true),
       set_config('pauk.direct_address', :'direct_address', true),
       set_config('pauk.expected_services', :'services', true);
DO $remove$
DECLARE
    state platform_ingress_config%ROWTYPE;
    entry_id text := current_setting('pauk.entry_id');
    entry_address text;
    remaining jsonb;
    next_primary text;
    next_secondary text;
BEGIN
    SELECT * INTO state FROM platform_ingress_config WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM set_config('pauk.result', 'missing', true);
        RETURN;
    END IF;
    IF state.revision <> current_setting('pauk.expected_revision')::bigint THEN
        PERFORM set_config('pauk.result', 'stale', true);
        RETURN;
    END IF;
    IF coalesce((state.config->>'vpn_enabled')::boolean, true)
       OR coalesce((state.config->>'web_enabled')::boolean, true) THEN
        PERFORM set_config('pauk.result', 'enabled', true);
        RETURN;
    END IF;
    IF EXISTS (SELECT FROM ingress_provision_runs WHERE status = 'running') THEN
        PERFORM set_config('pauk.result', 'running', true);
        RETURN;
    END IF;
    SELECT value->>'address' INTO entry_address
    FROM jsonb_array_elements(state.config->'entries')
    WHERE value->>'id' = entry_id;
    IF NOT FOUND THEN
        PERFORM set_config('pauk.result', 'missing', true);
        RETURN;
    END IF;
    IF entry_address IS DISTINCT FROM current_setting('pauk.expected_address')
       OR ({ENABLED_ADDRESSES}) <> current_setting('pauk.expected_services')::jsonb THEN
        PERFORM set_config('pauk.result', 'stale', true);
        RETURN;
    END IF;

    SELECT coalesce(jsonb_agg(value ORDER BY ord), '[]') INTO remaining
    FROM jsonb_array_elements(state.config->'entries') WITH ORDINALITY AS entries(value, ord)
    WHERE value->>'id' <> entry_id;

    next_primary := coalesce(state.config->>'primary_id', '');
    next_secondary := coalesce(state.config->>'secondary_id', '');
    IF next_secondary = entry_id THEN
        next_secondary := '';
    END IF;
    IF next_primary = entry_id THEN
        SELECT coalesce(nullif(next_secondary, ''), (
            SELECT value->>'id' FROM jsonb_array_elements(remaining)
            WHERE value->'ready' = 'true'::jsonb
            ORDER BY (value->>'id' = 'pauk-direct-publication') LIMIT 1
        ), '') INTO next_primary;
        IF next_secondary = next_primary THEN
            next_secondary := '';
        END IF;
    END IF;

    IF NOT EXISTS (
        SELECT FROM jsonb_array_elements(remaining)
        WHERE value->>'id' = next_primary AND value->'ready' = 'true'::jsonb
    ) THEN
        -- The controller requires a ready primary even with reserve disabled.
        -- This is the existing direct subscription edge, not a prepared ingress.
        next_primary := 'pauk-direct-publication';
        next_secondary := '';
        remaining := remaining || jsonb_build_array(jsonb_build_object(
            'id', next_primary, 'name', 'Прямая публикация подписок',
            'address', current_setting('pauk.direct_address'),
            'kind', 'native', 'ready', true, 'https_port', 443, 'panel_port', 8443,
            'check_status', '', 'check_details', '[]'::jsonb
        ));
    END IF;
    UPDATE platform_ingress_config
    SET revision = state.revision + 1,
        config = state.config || jsonb_build_object(
            'entries', remaining, 'primary_id', next_primary,
            'secondary_id', next_secondary, 'revision', state.revision + 1
        ),
        source_rules = coalesce((
            SELECT jsonb_agg(
                CASE WHEN value->>'fallback_address' = entry_address
                     THEN value - ARRAY['fallback_address','fallback_port','fallback_path','fallback_server_name']
                     ELSE value END ORDER BY ord)
            FROM jsonb_array_elements(state.source_rules) WITH ORDINALITY AS rules(value, ord)
            WHERE value->>'address' IS DISTINCT FROM entry_address
        ), '[]'),
        updated_at = now()
    WHERE singleton;

    DELETE FROM protocol_ingress_reports AS r WHERE r.entry_id = current_setting('pauk.entry_id');
    DELETE FROM protocol_ingress_entry_nodes AS n WHERE n.entry_id = current_setting('pauk.entry_id');
    PERFORM set_config('pauk.result', 'ok', true);
END
$remove$;
SELECT current_setting('pauk.result');
COMMIT;
"""

def database(query, **variables):
    flags = [part for key, value in variables.items() for part in ("-v", f"{key}={value}")]
    result = subprocess.run(DATABASE + flags, input=query, text=True, capture_output=True, timeout=5)
    if result.returncode:
        print("Database operation failed:", result.stderr.splitlines()[0][:240], file=sys.stderr)
        raise RuntimeError("database failure")
    return result.stdout.strip().splitlines()[-1] if result.stdout.strip() else None

def addresses(host):
    try:
        return {row[4][0] for row in socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        if error.errno in {socket.EAI_NONAME, socket.EAI_NODATA}:
            return set()
        raise

def remove(request):
    if not isinstance(request, dict) or set(request) != {"id", "revision"}:
        return "invalid"
    entry_id, revision = request["id"], request["revision"]
    if (not isinstance(entry_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", entry_id)
        or type(revision) is not int or not 1 <= revision <= 9007199254740991):
        return "invalid"
    raw_state = database(READ)
    if raw_state is None:
        return "missing"
    state = json.loads(raw_state)
    if state["revision"] != revision:
        return "stale"
    config = state["config"]
    if entry_id == "pauk-direct-publication":
        return "missing"
    if config["vpn_enabled"] or config["web_enabled"]:
        return "enabled"
    entry = next((item for item in config["entries"] if item["id"] == entry_id), None)
    if entry is None:
        return "missing"
    address = str(ipaddress.IPv4Address(entry["address"]))
    hosts = {
        "panel.pauk.click", "sub.pauk.click", config["panel_host"], config["subscription_host"],
        *config["legacy_hosts"], *state["services"],
    } - {""}
    try:
        if any(address in addresses(host) for host in sorted(hosts)):
            return "in_use"
        direct_addresses = addresses("sub.pauk.click")
        if len(direct_addresses) != 1:
            return "dns_unavailable"
        direct_address = next(iter(direct_addresses))
    except socket.gaierror:
        return "dns_unavailable"
    return database(
        DELETE, entry_id=entry_id, revision=revision, address=address,
        direct_address=direct_address,
        services=json.dumps(state["services"], separators=(",", ":")),
    )

def serve():
    with socket.socket(fileno=os.dup(0)) as connection:
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != pwd.getpwnam("vpnplatform-web").pw_uid:
            return
        connection.settimeout(2)
        with connection.makefile("rb") as request:
            payload = request.readline(512)
        if len(payload) >= 512 or not payload.endswith(b"\n"):
            status = "invalid"
        else:
            try:
                status = remove(json.loads(payload))
            except (UnicodeDecodeError, json.JSONDecodeError):
                status = "invalid"
            except Exception as error:
                print(f"Ingress removal failed: {type(error).__name__}", file=sys.stderr)
                status = "failed"
        connection.sendall(json.dumps({"status": status}).encode() + b"\n")

if __name__ == "__main__":
    with contextlib.suppress(ConnectionError, TimeoutError):
        serve()
