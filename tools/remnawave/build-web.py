#!/usr/bin/env python3
"""Build the repository web interface without the installed panel's secrets."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tarfile

source = Path(sys.argv[1])
state = Path(os.environ["STATE_DIRECTORY"])
work = state / "web"
with tarfile.open(source) as archive:
    members = archive.getmembers()
    if not all(entry.isfile() for entry in members):
        raise RuntimeError("Unexpected build input")
    archive.extractall(work, filter="data")
env = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": str(state),
    "NEXT_TELEMETRY_DISABLED": "1",
    "CI": "1",
    "NODE_ENV": "production",
    "CONTROL_PLANE_URL": "http://127.0.0.1:8080",
    "CONTROL_PLANE_ADMIN_TOKEN": "build-only",
    "WEB_ADMIN_USER": "build-only",
    "WEB_ADMIN_PASSWORD_HASH": "build-only",
    "WEB_SESSION_SECRET": "build-only-session-secret",
    "VPN_PLATFORM_PUBLIC_URL": "https://panel.example.com",
    "VPN_PLATFORM_SUBSCRIPTION_URL": "https://panel.example.com",
}
subprocess.run(["npm", "ci", "--include=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
               cwd=work, env=env, check=True, timeout=300)
subprocess.run(["npm", "run", "build"], cwd=work, env=env, check=True, timeout=360)
standalone = work / ".next/standalone"
shutil.copytree(work / "public", standalone / "public")
shutil.copytree(work / ".next/static", standalone / ".next/static")
