#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -f /opt/vpn-platform/web/standalone/package.json ]]; then
    exec python3 "$ROOT/tools/remnawave/update.py"
fi
bash "$ROOT/install.sh" "$@"
exec python3 "$ROOT/tools/remnawave/update.py"
