#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if (( EUID != 0 )); then
    echo 'Run with sudo' >&2
    exit 1
fi
if [[ ! -e /var/lib/vpn-platform/lifecycle-state.json ]]; then
    bash "$root/install.sh" "$@"
elif (( $# != 0 )); then
    echo 'An existing installation uses its saved settings. Run the upgrade without installer options.' >&2
    exit 1
fi
exec python3 "$root/tools/0103-upgrade.py"
