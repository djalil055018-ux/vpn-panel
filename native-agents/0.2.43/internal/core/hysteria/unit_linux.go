//go:build linux

package hysteria

import (
	"fmt"
	"path/filepath"
	"regexp"
)

const ManagedAgentService = "vpn-platform-node-agent.service"

var managedAgentUnitName = regexp.MustCompile(`^vpn-platform-node-agent(?:-candidate-[0-9a-f]{16})?\.service$`)
var unitBasePath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

// Render only; publication and daemon-reload require the node installer guard.
// No WantedBy section: only a reconciled, leased agent starts this runtime.
// BindsTo+After stops the core if its owning agent unexpectedly becomes inactive,
// including when the agent cannot run its normal authorization cleanup callback.
func renderManagedUnit(base string, uid, gid int, owner string) ([]byte, error) {
	return renderManagedUnitWithAgent(base, uid, gid, owner, "/usr/local/bin/vpn-node-agent")
}
func renderManagedUnitWithAgent(base string, uid, gid int, owner, agentBinary string) ([]byte, error) {
	if !validRuntimeIdentity(uid, gid) || base == "/" || !unitBasePath.MatchString(base) || filepath.Clean(base) != base || !managedAgentUnitName.MatchString(owner) {
		return nil, ErrSystemdRuntime
	}
	if agentBinary == "/" || !unitBasePath.MatchString(agentBinary) || filepath.Clean(agentBinary) != agentBinary {
		return nil, ErrSystemdRuntime
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=VPN Platform Managed Hysteria 2
After=network-online.target %s
BindsTo=%s
Wants=network-online.target

[Service]
Type=simple
User=%d
Group=%d
ExecStart=%s/hysteria2/current/hysteria server -c %s/hysteria2/current/config.json
ExecStop=+%s capture-traffic --data-dir %s --unit %%n
Restart=on-failure
RestartSec=2
TimeoutStopSec=15
KillMode=control-group
SendSIGKILL=yes
FinalKillSignal=SIGKILL
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077
LimitCORE=0
LimitNOFILE=1048576
StandardOutput=null
StandardError=null
`, owner, owner, uid, gid, base, base, agentBinary, base)), nil
}
