#!/usr/bin/env python3
"""Update the Remnawave migration feature on a public v0.1.155 installation."""
import argparse
import contextlib
import fcntl
import grp
import http.client
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CURRENT_WEB = "0.12.71"
TARGET_WEB = "0.12.72"
CONTROL_VERSION = "0.1.150"
WEB_ROOT = Path("/opt/vpn-platform/web")
WEB = "vpn-platform-web.service"
SOCKET = "pauk-remnawave-native.socket"
TIMER = "pauk-remnawave-quota-reset.timer"
RESET = "pauk-remnawave-quota-reset.service"
SITE = Path("/etc/nginx/sites-available/pauk-platform")
LIBEXEC = Path("/usr/local/libexec")
EXPORTER = Path("/opt/pauk-remnawave-3411-release/export.py")
DB = ["docker", "exec", "-i", "vpn-platform-postgres", "sh", "-ec"]
PSQL = 'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'


def run(*args, **options):
    return subprocess.run(args, check=True, timeout=options.pop("timeout", 35), **options)


def get(port, path):
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=4)) as connection:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read(1 << 20)


def ready():
    until = time.monotonic() + 20
    while time.monotonic() < until:
        try:
            if get(3000, "/login")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(.4)
    raise RuntimeError("Панель не ответила после обновления")


def site_config(before):
    marker = "    location / {\n"
    if before.count(marker) != 1 or "# PAUK self-hosted site:" not in before:
        raise RuntimeError("Ожидалась стандартная конфигурация Nginx из публичного установщика")
    block = before.partition(marker)[2].partition("\n    }")[0]
    if "proxy_pass http://127.0.0.1:3000;" not in block:
        raise RuntimeError("Маршрут веб-панели был изменён")
    overridden = {"client_max_body_size", "proxy_read_timeout", "proxy_request_buffering"}
    block = "\n".join(
        line for line in block.split("\n")
        if not line.strip().split(maxsplit=1) or line.strip().split(maxsplit=1)[0] not in overridden
    )
    protocol = "" if "proxy_http_version" in block else "        proxy_http_version 1.1;\n"
    return before.replace(marker, '''    location ~ "^/migrations/remnawave/(capture|snapshot)/?$" {
        client_max_body_size 64m;
        proxy_read_timeout 80s;
        proxy_request_buffering off;
''' + protocol + block + "\n    }\n\n" + marker, 1)


def current_version(path):
    return json.loads((path / "package.json").read_text())["version"]


def write_atomic(path, data, mode=0o644):
    path.parent.mkdir(exist_ok=True, parents=True)
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp.chmod(mode)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def build(identifier, candidate):
    with tarfile.open(candidate, "w:gz") as archive:
        web = ROOT / "web"
        for item in ("src", "public", "package.json", "package-lock.json", "next.config.ts",
                     "tsconfig.json", "postcss.config.mjs", "eslint.config.mjs"):
            source = web / item
            files = sorted(source.rglob("*")) if source.is_dir() else [source]
            for path in files:
                if path.is_symlink():
                    raise RuntimeError("Недопустимая ссылка в исходниках")
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(web).as_posix(), recursive=False)
    worker = candidate.with_suffix(".py")
    worker.write_bytes((HERE / "build-web.py").read_bytes())
    candidate.chmod(0o644)
    worker.chmod(0o644)
    run("systemd-run", "--wait", "--collect", "--pipe", "--unit=" + identifier,
        "--property=DynamicUser=yes", "--property=StateDirectory=" + identifier,
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
        "--property=NoNewPrivileges=yes", "--property=InaccessiblePaths=/opt/vpn-platform /etc/vpn-platform /run/docker.sock",
        "--property=RuntimeMaxSec=720", "--property=MemoryMax=2800M",
        "/usr/bin/python3", str(worker), str(candidate), timeout=740)
    return Path("/var/lib/private") / identifier / "web/.next/standalone"


def apply(check):
    status, body = get(8080, "/healthz")
    if status != 200 or json.loads(body).get("version") != CONTROL_VERSION:
        raise RuntimeError("Поддерживается публичная установка v0.1.155 с Control Plane 0.1.150")
    live = WEB_ROOT / "standalone"
    installed = current_version(live)
    if installed == TARGET_WEB:
        run("systemctl", "is-active", WEB, SOCKET, TIMER)
        print("Обновление уже установлено")
        return
    if installed != CURRENT_WEB:
        raise RuntimeError("Текущая версия интерфейса несовместима с этим обновлением")
    if SITE.is_symlink():
        raise RuntimeError("Конфигурация Nginx является ссылкой")
    new_site = site_config(SITE.read_text())
    run("nginx", "-t")
    run("systemctl", "is-active", WEB, "vpn-platform-control-plane.service")
    run(*DB, PSQL, input=b"SELECT count(*) FROM remnawave_imports;", capture_output=True)
    if check:
        print("Установка совместима с обновлением Remnawave")
        return

    identifier = "pauk-remnawave-build-" + uuid.uuid4().hex[:10]
    backup = Path("/var/backups/vpn-platform") / identifier
    backup.mkdir(mode=0o700, parents=True)
    build_path = Path("/opt") / (identifier + ".tgz")
    candidate = build(identifier, build_path)
    if current_version(candidate) != TARGET_WEB or not (candidate / "server.js").is_file():
        raise RuntimeError("Версия собранного интерфейса не совпадает с выпуском")
    pending = WEB_ROOT / (identifier + "-pending")
    old_web = WEB_ROOT / (identifier + "-previous")
    group = grp.getgrnam("vpnplatform-web").gr_gid
    import shutil
    shutil.copytree(candidate, pending)
    for path in (pending, *pending.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("Недопустимая ссылка в веб-сборке")
        os.chown(path, 0, group)
        path.chmod(0o750 if path.is_dir() or path.stat().st_mode & 0o111 else 0o640)

    dump = backup / "database.dump"
    with dump.open("xb") as handle:
        run(*DB, 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"', stdout=handle, timeout=180)
    with dump.open("rb") as handle:
        run(*DB, "exec pg_restore --list", stdin=handle, stdout=subprocess.DEVNULL)
    units = Path("/etc/systemd/system")
    resources = {
        EXPORTER: (HERE / "export.py").read_bytes(),
        LIBEXEC / "pauk-remnawave-native.py": (HERE / "activate.py").read_bytes(),
        LIBEXEC / "pauk-remnawave-quota-reset.py": (HERE / "reset.py").read_bytes(),
        SITE: new_site.encode(),
    }
    for name in (SOCKET, TIMER, RESET, "pauk-remnawave-native@.service"):
        resources[units / name] = (HERE / name).read_bytes()
    previous = {}
    for index, path in enumerate(resources):
        if path.is_symlink():
            raise RuntimeError("Недопустимая ссылка в конфигурации")
        if path.exists():
            previous[path] = path.read_bytes()
            write_atomic(backup / (str(index) + "-" + path.name), previous[path], 0o600)

    enabled_before = {unit for unit in (SOCKET, TIMER) if subprocess.run(
        ["systemctl", "is-enabled", "--quiet", unit], check=False).returncode == 0}
    moved = False
    try:
        run(*DB, PSQL, input=(HERE / "quota-schedules.sql").read_bytes(), timeout=25)
        for path, content in resources.items():
            write_atomic(path, content)
        run("nginx", "-t")
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", SOCKET, TIMER)
        run("systemctl", "stop", WEB)
        live.rename(old_web)
        moved = True
        pending.rename(live)
        run("systemctl", "start", WEB)
        ready()
        run("systemctl", "reload", "nginx")
    except BaseException:
        for unit in (SOCKET, TIMER):
            if unit not in enabled_before:
                subprocess.run(["systemctl", "disable", "--now", unit], check=False)
        for path in resources:
            if path in previous:
                write_atomic(path, previous[path])
            else:
                path.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        if moved:
            run("systemctl", "stop", WEB)
            if live.exists():
                live.rename(WEB_ROOT / (identifier + "-failed"))
            old_web.rename(live)
        run("systemctl", "start", WEB)
        run("nginx", "-t")
        run("systemctl", "reload", "nginx")
        raise
    print("Обновление установлено. Резервная копия:", backup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Требуется запуск через sudo")
    os.umask(0o077)
    with Path("/run/lock/pauk-remnawave-update.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        apply(args.check)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
