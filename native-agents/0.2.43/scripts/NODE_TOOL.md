# Node lifecycle tool 0.2.22

Requires Ubuntu 24.04 amd64, Python 3, systemd, and Control Plane >= 0.1.80.
Run as root. The tool downloads the pinned agent artifact over HTTPS and verifies
SHA-256 before replacing files. Bootstrap credentials are requested with hidden
terminal input; automation can use an owner-only `--bootstrap-token-file`.
Never include credentials in command arguments.

```
python3 /root/vpn-node-tool.py install
python3 /root/vpn-node-tool.py status
python3 /root/vpn-node-tool.py upgrade
python3 /root/vpn-node-tool.py repair
python3 /root/vpn-node-tool.py rollback --backup BACKUP_ID
```

`install` registers an unregistered node and starts its agent. Existing registration
is reused. `upgrade` is idempotent when the pinned version is already healthy.
`repair` reinstalls the pinned agent and standard service definition while preserving
registration, data, and existing configuration values. Custom data paths are rejected
before changes. A different Control Plane origin can be supplied with `--control-plane`.

Before a change, the tool stores binary/configuration backups and a protected archive
of agent state, REALITY material and certificates under
`/var/backups/vpn-platform/node-tool/BACKUP_ID`. A five-minute systemd timer restores
the previous executable and service configuration if the operation is interrupted.
The change commits only after the Control Plane confirms a fresh online report,
the expected agent version, and applied/desired generation convergence.

Rollback does not replace registration, applied state, REALITY keys, certificates,
or Xray configuration with an old snapshot. It also does not stop the separate Xray
service. For a failed first installation, consumed registration is retained for a
retry. The state archive is reserved for deliberate disaster recovery.

The tool never prints tokens or raw service logs. `status` uses the node's own
permanent credential in memory to request safe lifecycle metadata. No administrator
credential is required on the node. This tool manages the node agent, not OS packages,
the Control Plane installation, or VPN core release rollouts.

Version 0.2.20 reports one-minute CPU, load, memory, disk, network-counter and
uptime samples. The Control Plane stores only aggregate host measurements; the
agent does not send process lists, addresses, credentials or configuration data.
It also reports cumulative per-client traffic and only the number of currently
observed client addresses. Raw network addresses remain on the node and are never
included in health reports.

Version 0.2.22 adds the Xray systemd invocation ID and a durable monotonically
increasing sample sequence. The sequence lives beside the agent state in
`traffic-sequence`; keep it during repair, upgrade and rollback. A corrupt
checkpoint stops traffic sampling rather than restarting the sequence at zero.
Control Plane ignores old, duplicate and legacy reports after an ordered cursor
has been established. Rolling an agent back below 0.2.22 therefore pauses its
traffic accounting until a compatible agent is restored; VPN health reporting
continues. Before downgrading Control Plane below 0.1.80, downgrade agents first
because earlier servers do not recognize the new health-report field.
