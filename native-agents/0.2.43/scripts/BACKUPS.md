# Verified local backups and application restore drill v0.2

The root-owned `/usr/local/libexec/vpn-platform/platform-backup.py` creates protected local snapshots. It never restores data into the production database. The daily systemd timer runs at 02:30 UTC with up to 15 minutes of jitter and keeps the latest seven verified snapshots.

Control Plane snapshots include a PostgreSQL custom dump, application configuration, source and executable files, web source/public assets/build configuration, maintenance scripts, certificate configuration and service units. Verification checks file hashes, reads the archive and restores the dump into a uniquely created disposable database. That database is removed after the check; existing databases are never selected as restore targets.

Node snapshots include registration, agent configuration and executable, desired-state files, keys, certificates and Xray configuration. Verification checks hashes and archive readability. Historical core executables are not included. An archive-integrity check is not a complete server recovery drill.

Storage: `/var/backups/vpn-platform/managed/control-plane/` or `.../node/`, accessible only to root. These archives contain secrets and must never be published or placed in the web root. Retention only removes verified snapshots in these managed directories; manual backups and failed/incomplete snapshots are preserved.

Safe metadata lives in `/var/lib/vpn-platform/operations/`. Nodes report only metadata using their own existing agent credential; the panel shows backup age, verification type and status. Node reports refresh hourly. A copy older than 36 hours is flagged.

Root maintenance commands:

```sh
python3 /usr/local/libexec/vpn-platform/platform-backup.py control-plane status
python3 /usr/local/libexec/vpn-platform/platform-backup.py control-plane create --keep 7
python3 /usr/local/libexec/vpn-platform/platform-backup.py control-plane verify --id BACKUP_ID
python3 /usr/local/libexec/vpn-platform/platform-backup.py node status
python3 /usr/local/libexec/vpn-platform/platform-backup.py node report
systemctl list-timers vpn-platform-managed-backup.timer
```

Replace the role with the actual host role. `verify` on the Control Plane runs another isolated restore. Do not manually extract a backup over a running installation. The database and files are captured sequentially, so changes during capture are not a coordinated distributed snapshot.

Failure handling: the backup unit records a generic failure without exposing command output or credentials; previous successful-copy metadata remains available. Inspect storage capacity, service exit state and safe metadata first. Investigate private archives or raw diagnostics only in a protected administrative session.

## Application restore drill

After a verified Control Plane backup, root can run:

```sh
python3 /usr/local/libexec/vpn-platform/platform-restore-drill.py --id BACKUP_ID
```

The helper checks hashes, extracts only selected regular application/configuration files into a protected temporary directory, creates a uniquely named `vpn_restore_drill_<16 hex digits>` database, restores it and sets its default transactions to read-only. It starts the archived Control Plane binary with a fresh temporary admin key on a random loopback port. API results are compared with restored database counts. No background workers or node agents are started.

The web app is rebuilt from the archived source and exact package lock with freshly installed dependencies, its standalone runtime is assembled with the public and static assets, then started on another loopback port with an independent temporary session key. Twelve authenticated pages (including tenant limits) and absence of temporary admin/session secrets in HTML are checked. The processes, temporary database and extracted directory are removed in cleanup. SIGTERM/SIGINT trigger cleanup; a host crash or SIGKILL can leave protected temporary resources requiring an explicit, exact-path administrative cleanup.

Safe results in `/var/lib/vpn-platform/operations/restore-drill.json` appear under **Проверка восстановления** on `/operations` in Control Plane 0.1.70+. Results name the tested backup/version; a later release requires a new drill. A failed drill does not mark an otherwise intact backup as corrupt. Drills share the backup lock and require 4 GiB free space. They currently run manually, using the host's existing PostgreSQL container, Node.js and npm; package installation requires registry access.

Limits: no offsite copy, storage-loss protection, bare-metal recovery, automated failover, node application recovery drill or scheduled application drill is supplied. This verifies database and application boot on the current host, not restoration of the entire server or production traffic cutover. A separate target still needs compatible runtime/core installation, firewall/DNS/service setup, credential protection and explicit validation before changing production.
