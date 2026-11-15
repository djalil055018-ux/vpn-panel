#!/usr/bin/env python3
"""Install PAUK 0.12.103 over the public self-hosted distribution, with rollback."""
import argparse
import contextlib
import fcntl
import grp
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = ROOT / "checkpoints/pauk-0.12.103"
DIST = ROOT / "distribution/0.12.103"
WEB = "vpn-platform-web.service"
CONTROL = "vpn-platform-control-plane.service"
LIBEXEC = Path("/usr/local/libexec")
UNITS = Path("/etc/systemd/system")
ENV = Path("/etc/vpn-platform")
PKG = Path("/opt/vpn-platform")
STATE = Path("/var/lib/vpn-platform/pauk-0.12.103.json")
SITE = Path("/etc/nginx/sites-available/pauk-platform")
LIFECYCLE = Path("/var/lib/vpn-platform/lifecycle-state.json")
PUBLIC = Path("/var/www/vpn-platform-public")

spec = importlib.util.spec_from_file_location("database", ROOT / "tools/0103-database.py")
database = importlib.util.module_from_spec(spec)
spec.loader.exec_module(database)


def run(*args, **options):
    return subprocess.run(args, check=True, timeout=options.pop("timeout", 40), **options)


def unit_active(unit):
    return subprocess.run(["systemctl", "is-active", "--quiet", unit], capture_output=True).returncode == 0


def query(port, path):
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=3)) as connection:
        connection.request("GET", path)
        reply = connection.getresponse()
        return reply.status, reply.read(1 << 20)


def health(version):
    until = time.monotonic() + 28
    while time.monotonic() < until:
        try:
            status, body = query(8080, "/healthz")
            if status == 200 and json.loads(body).get("version") == version and query(3000, "/login")[0] == 200:
                return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        time.sleep(.4)
    raise RuntimeError("Expected Control Plane and web interface were not ready")


def auth_env(path):
    import shlex
    result = {}
    for line in path.read_text().splitlines():
        key, equals, remainder = line.partition("=")
        if equals and re.fullmatch(r"[A-Z][A-Z0-9_]+", key):
            parts = shlex.split(remainder, comments=False)
            if len(parts) == 1:
                result[key] = parts[0]
    return result


def ingress_defaults(address=None):
    configured = auth_env(ENV / "web.env")
    panel = urlsplit(configured["VPN_PLATFORM_PUBLIC_URL"])
    subscription = urlsplit(configured.get("VPN_PLATFORM_SUBSCRIPTION_URL") or panel.geturl())
    if address is None:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(
                panel.hostname, panel.port or 443, socket.AF_INET, socket.SOCK_STREAM)}
        except socket.gaierror:
            return b""
        if len(addresses) != 1:
            return b""
        address = addresses.pop()
    ipv4 = ipaddress.IPv4Address(address)
    if not ipv4.is_global or ipv4.is_multicast or ipv4.is_reserved:
        return b""
    if not panel.hostname or not subscription.hostname:
        return b""
    entry_id = "pauk-direct-publication"
    config = {
        "revision": 1, "vpn_enabled": False, "web_enabled": False,
        "primary_id": entry_id, "secondary_id": "", "probe_interval_seconds": 60,
        "panel_host": panel.hostname, "subscription_host": subscription.hostname,
        "legacy_hosts": [],
        "entries": [{
            "id": entry_id, "name": "Основной HTTPS-вход", "address": str(ipv4),
            "https_port": subscription.port or 443, "panel_port": panel.port or 443,
            "kind": "native", "ready": True, "check_status": "configured", "check_details": [],
        }],
    }
    encoded = json.dumps(config).encode().hex()
    return (f"INSERT INTO platform_ingress_config(config,source_rules) "
            f"VALUES (convert_from(decode('{encoded}','hex'),'UTF8')::jsonb,'[]') "
            "ON CONFLICT(singleton) DO NOTHING;\n").encode()


def package_version(path):
    return json.loads((path / "package.json").read_text())["version"]


def check():
    if not SITE.is_file() or SITE.is_symlink() or "# PAUK self-hosted site:" not in SITE.read_text():
        raise RuntimeError("This upgrade expects the public self-hosted Nginx layout")
    if not LIFECYCLE.is_file():
        raise RuntimeError("PAUK lifecycle marker is missing")
    web = package_version(PKG / "web/standalone")
    status, body = query(8080, "/healthz")
    version = json.loads(body).get("version") if status == 200 else None
    if web == "0.12.103" and version == "0.1.178" and STATE.is_file():
        return None
    if web not in {"0.12.71", "0.12.72"} or version != "0.1.150":
        raise RuntimeError("Supported input is public release 0.1.155 with web 0.12.71 or 0.12.72")
    if not unit_active(WEB) or not unit_active(CONTROL):
        raise RuntimeError("The installed panel must be running")
    web_env = auth_env(ENV / "web.env")
    control_env = auth_env(ENV / "control-plane.env")
    origin = urlsplit(web_env["VPN_PLATFORM_PUBLIC_URL"])
    if origin.scheme != "https" or not origin.hostname or origin.path not in {"", "/"}:
        raise RuntimeError("The configured panel origin is invalid")
    db = database.stock_database()
    if urlsplit(control_env["DATABASE_URL"]).path != "/" + db:
        raise RuntimeError("Configured database differs from the standard PostgreSQL container")
    database.check_stock(db)
    run("nginx", "-t")
    return db


def add_env(data, key, value):
    if re.search(rb"(?m)^" + key.encode() + b"=", data):
        return data
    return data.rstrip(b"\n") + b"\n" + key.encode() + b"=" + value.encode() + b"\n"


def extract(name, paths, archive_hash, files, location):
    archive = location.parent / name
    checksum = hashlib.sha256()
    with archive.open("xb") as output:
        for part in paths:
            raw = part.read_bytes()
            output.write(raw)
            checksum.update(raw)
    if checksum.hexdigest() != archive_hash:
        raise RuntimeError("Release archive checksum did not match")
    location.mkdir()
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        if sorted(m.name for m in members) != sorted(files):
            raise RuntimeError("Release manifest does not match the archive")
        for member in members:
            target = Path(member.name)
            if target.is_absolute() or ".." in target.parts or not member.isfile():
                raise RuntimeError("Unsafe release archive member")
            digest = hashlib.sha256(bundle.extractfile(member).read()).hexdigest()
            if digest != files[member.name]["sha256"] or member.size != files[member.name]["bytes"]:
                raise RuntimeError("Release member checksum did not match")
        bundle.extractall(location, filter="data")
    archive.unlink()


def atomic(path, contents, mode):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def asset_directories(path):
    relative = path.relative_to(PUBLIC)
    directory = PUBLIC
    for part in relative.parts[:-1]:
        directory /= part
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RuntimeError("Unsafe public artifact directory")
        if not directory.exists():
            directory.mkdir()
            directory.chmod(0o755)


def tree_build(staging, uid):
    archive = staging / "web.tgz"
    source = CHECKPOINT / "web"
    with tarfile.open(archive, "w:gz") as bundle:
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise RuntimeError("Unexpected symlink in web source")
            if path.is_file():
                bundle.add(path, arcname=path.relative_to(source).as_posix(), recursive=False)
    archive.chmod(0o644)
    worker = staging / "build.py"
    shutil.copyfile(ROOT / "tools/remnawave/build-web.py", worker)
    worker.chmod(0o644)
    run("systemd-run", "--wait", "--pipe", "--collect", "--unit=" + uid,
        "--property=DynamicUser=yes", "--property=StateDirectory=" + uid,
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
        "--property=NoNewPrivileges=yes", "--property=MemoryMax=2600M",
        "--property=InaccessiblePaths=/opt/vpn-platform /etc/vpn-platform /run/docker.sock",
        "/usr/bin/python3", str(worker), str(archive), timeout=780)
    path = Path("/var/lib/private") / uid / "web/.next/standalone"
    if package_version(path) != "0.12.103":
        raise RuntimeError("Incorrect web release version")
    return path


def nginx_config(old):
    spec = importlib.util.spec_from_file_location("seller", ROOT / "tools/remnawave/update.py")
    seller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seller)
    result = old if "migrations/remnawave/(capture|snapshot)" in old else seller.site_config(old)
    subscription = "    location ^~ /sub/ {"
    if result.count(subscription) != 1:
        raise RuntimeError("The standard subscription proxy could not be identified")
    result = result.replace(subscription, """    location ^~ /sub/ {
        proxy_hide_header announce;
        add_header announce $pauk_seller_announce;""", 1)
    return """js_import seller_announce from /etc/nginx/pauk-seller-announcement.js;
js_set $pauk_seller_announce_value seller_announce.value;
map "$http_user_agent|$upstream_status|$upstream_http_content_type" $pauk_seller_announce {
    default $upstream_http_announce;
    "~*INCY[^|]*\\|200\\|(?!text/html)" $pauk_seller_announce_value;
}
""" + result



def validate_public_proxy():
    origin = urlsplit(auth_env(ENV / "web.env")["VPN_PLATFORM_PUBLIC_URL"])
    required = (
        "/healthz", "/login",
        "/install/install-ingress-agent-v0.1.4.py", "/install/pauk-node-cover-v0.1.2.py",
        "/artifacts/node-agent/0.2.51/linux-amd64/vpn-node-agent",
        "/artifacts/cores/amneziawg/3.1.20260828-pauk.1/linux-amd64.tar.gz",
    )
    for path in required:
        run("curl", "--fail", "--silent", "--show-error", "--head", "--max-time", "8",
            "--retry", "3", "--retry-connrefused", "--output", "/dev/null",
            "--resolve", f"{origin.hostname}:{origin.port or 443}:127.0.0.1",
            origin.geturl().rstrip("/") + path)

def services():
    result = run("systemctl", "list-timers", "--all", "--no-legend", "--no-pager", stdout=subprocess.PIPE).stdout.decode()
    timers = {word for line in result.splitlines() for word in line.split() if re.fullmatch(r"(?:vpn-platform|pauk-remnawave)[a-z0-9-]*\.timer", word)}
    return sorted(timer for timer in timers if unit_active(timer))


def release_resources(controller, assets):
    support = CHECKPOINT / "support"
    items = {
        ENV / "control-plane.env": (add_env((ENV / "control-plane.env").read_bytes(),
            "ADMIN_MFA_ENCRYPTION_KEY", secrets.token_urlsafe(32)), 0o600),
        SITE: (nginx_config(SITE.read_text()).encode(), 0o644),
        Path("/etc/nginx/pauk-seller-announcement.js"): ((support / "announcement/nginx-announcement.js").read_bytes(), 0o644),
        UNITS / "vpn-platform-web.service.d/subscription-announcement.conf": ((support / "announcement/web-state.conf").read_bytes(), 0o644),
        Path("/opt/pauk-remnawave-3411-release/export.py"): ((support / "remnawave/export.py").read_bytes(), 0o644),
        LIBEXEC / "pauk-remnawave-native.py": ((support / "remnawave/activate.py").read_bytes(), 0o644),
        LIBEXEC / "pauk-remnawave-quota-reset.py": ((support / "remnawave/reset.py").read_bytes(), 0o644),
        LIBEXEC / "pauk-ingress-delete.py": ((DIST / "seller-ingress-delete.py").read_bytes(), 0o644),
    }
    for path in (support / "systemd").iterdir():
        items[UNITS / path.name] = (path.read_bytes(), 0o644)
    for path in (controller / "bin").iterdir():
        if path.name == "incident-monitor":
            continue  # Keep the self-hosted monitor and its local-only targets.
        items[PKG / "bin" / path.name] = (path.read_bytes(), 0o755)
    for dir in (assets, DIST / "node-tools"):
        for path in dir.rglob("*"):
            if path.is_file():
                target = PUBLIC / path.relative_to(dir)
                if target.exists() and target.read_bytes() != path.read_bytes():
                    raise RuntimeError(f"An existing node artifact differs: {path.name}")
                if not target.exists():
                    items[target] = (path.read_bytes(), 0o644)
    return items


def initialize_announcement():
    import pwd
    folder = Path("/var/lib/pauk-subscription-announcement")
    folder.mkdir(mode=0o755, exist_ok=True)
    account = pwd.getpwnam("vpnplatform-web")
    os.chown(folder, account.pw_uid, account.pw_gid)
    announcement = folder / "announce.b64"
    if not announcement.exists():
        atomic(announcement, b"", 0o644)
        os.chown(announcement, account.pw_uid, account.pw_gid)


def upgrade(db):
    revision = secrets.token_hex(6)
    unit = "pauk-0103-build-" + revision
    target, retained, failed = ("pauk_next_" + revision, "pauk_previous_" + revision, "pauk_failed_" + revision)
    backup = Path("/var/backups/vpn-platform") / unit
    backup.mkdir(mode=0o700, parents=True)
    stage = Path("/opt") / unit
    stage.mkdir(mode=0o755)
    stage.chmod(0o755)
    print("Verifying package and building web 0.12.103вЂ¦", flush=True)
    runtime = json.loads((CHECKPOINT / "controller-checkpoint-manifest.json").read_text())
    files = {"bin/" + key: value for key, value in runtime["binaries"].items()}
    extract("controller.tgz", [CHECKPOINT / row["name"] for row in runtime["parts"]],
            runtime["archive_sha256"], files, stage / "controller")
    node_assets = json.loads((DIST / "assets-manifest.json").read_text())
    extract("agents.tgz", sorted(DIST.glob("node-assets-0.12.103.tgz.part-*")),
            node_assets["archive_sha256"], node_assets["files"], stage / "node-assets")
    candidate = tree_build(stage, unit)
    path = PKG / "web"
    pending, live, previous = path / ("pending-" + revision), path / "standalone", path / ("previous-" + revision)
    shutil.copytree(candidate, pending, symlinks=True)
    group = grp.getgrnam("vpnplatform-web").gr_gid
    for file in (pending, *pending.rglob("*")):
        if file.is_symlink():
            raise RuntimeError("Unexpected symlink in web build")
        os.chown(file, 0, group)
        file.chmod(0o750 if file.is_dir() or file.stat().st_mode & 0o111 else 0o640)

    run("apt-get", "install", "-y", "--no-install-recommends", "libnginx-mod-http-js",
        env=os.environ | {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"}, timeout=240)
    items = release_resources(stage / "controller", stage / "node-assets")
    originals = {}
    for index, file in enumerate(items):
        if file.is_symlink():
            raise RuntimeError(f"Upgrade requires a regular file: {file}")
        if file.exists():
            originals[file] = (file.read_bytes(), file.stat().st_mode & 0o777)
            atomic(backup / ("file-" + str(index)), originals[file][0], 0o600)
    atomic(backup / "file-map.json", json.dumps([
        {"path": str(file), "mode": originals[file][1] if file in originals else None}
        for file in items
    ]).encode(), 0o600)
    private = stage / "private"
    private.mkdir(mode=0o700)
    timers = services()
    seed = (DIST / "seed.sql").read_bytes() + ingress_defaults()
    sockets = ("pauk-remnawave-native.socket", "pauk-ingress-delete.socket", "pauk-remnawave-quota-reset.timer")
    prior_sockets = [name for name in sockets if unit_active(name)]
    stopped = switched = moved = False
    written = []
    try:
        print("Creating a verified database copy. Panel maintenance starts now.", flush=True)
        stopped = True
        services_to_stop = [timer.removesuffix(".timer") + ".service" for timer in timers]
        run("systemctl", "stop", *timers, *services_to_stop, *prior_sockets, WEB, CONTROL)
        count, rows = database.prepare(db, target, private, backup, seed, DIST)
        print(f"Verified {rows} rows across {count} existing tables", flush=True)
        for file, (contents, mode) in items.items():
            if file.is_relative_to(PUBLIC):
                asset_directories(file)
            atomic(file, contents, mode)
            written.append(file)
        initialize_announcement()
        run("nginx", "-t")
        run("systemctl", "daemon-reload")
        database.switch(db, target, retained)
        switched = True
        live.rename(previous)
        moved = True
        pending.rename(live)
        run("systemctl", "start", CONTROL, WEB)
        health("0.1.178")
        run("systemctl", "enable", "--now", *sockets)
        if timers:
            run("systemctl", "start", *timers)
        run("systemctl", "reload", "nginx")
        validate_public_proxy()
        atomic(STATE, json.dumps({"web": "0.12.103", "control_plane": "0.1.178",
              "backup": str(backup), "previous_database": retained, "rows": rows, "tables": count}).encode(), 0o600)
        print("PAUK 0.12.103 is ready. Database and previous configuration saved in", backup)
    except BaseException:
        if stopped:
            subprocess.run(["systemctl", "stop", *sockets, *timers, WEB, CONTROL], check=False)
        for file in reversed(written):
            if file in originals:
                atomic(file, *originals[file])
            else:
                file.unlink(missing_ok=True)
        if moved:
            if live.exists():
                live.rename(path / ("failed-" + revision))
            previous.rename(live)
        if switched:
            database.switch(db, retained, failed)
        run("systemctl", "daemon-reload")
        subprocess.run(["systemctl", "disable", "--now", *[name for name in sockets if name not in prior_sockets]], check=False)
        if stopped:
            run("systemctl", "start", CONTROL, WEB, *timers, *prior_sockets)
        run("nginx", "-t")
        run("systemctl", "reload", "nginx")
        health("0.1.150")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true")
    action.add_argument("--initialize-ingress", metavar="PUBLIC_IPV4")
    args = parser.parse_args()
    if os.geteuid():
        parser.error("Run with sudo")
    os.umask(0o077)
    with Path("/run/lock/pauk-0103-upgrade.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = check()
        if args.initialize_ingress:
            if db is not None:
                parser.error("Install PAUK 0.12.103 first")
            seed = ingress_defaults(args.initialize_ingress)
            if not seed:
                parser.error("Use the public IPv4 address of your existing HTTPS entry")
            database.psql(database.stock_database(), seed)
            print("The HTTPS entry is initialized. Existing rules were preserved.")
        elif db is None:
            print("PAUK 0.12.103 is already installed")
        elif args.check:
            print("Public PAUK installation is compatible")
        else:
            upgrade(db)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        # Local service logs can contain SQL records. Keep them out of the console.
        print("Upgrade failed while running", Path(error.cmd[0]).name, file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        raise SystemExit(str(error)) from None
