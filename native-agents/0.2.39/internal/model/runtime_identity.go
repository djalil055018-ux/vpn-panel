package model

import (
	"strconv"
	"strings"
)

// RuntimeCore is selected when a node is created. Migration between cores needs
// a separately provisioned node, not a change to its desired state or agent.
func ValidRuntimeCore(value string) bool {
	return value == "xray" || value == "hysteria2" || value == "openvpn" || value == "wireguard" || value == "pptp"
}

func PPTPAgentCompatible(version string) bool { return agentMinimumPatch(version, 30) }

func OpenVPNAgentCompatible(version string) bool { return agentMinimumPatch(version, 27) }

func HysteriaAgentCompatible(version string) bool {
	return agentMinimumPatch(version, 24)
}
func agentMinimumPatch(version string, patch uint64) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	var numbers [3]uint64
	for i, part := range parts {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != part {
			return false
		}
		numbers[i] = number
	}
	return numbers[0] > 0 || numbers[1] > 2 || (numbers[1] == 2 && numbers[2] >= patch)
}

func NativeWireGuardAgentCompatible(version string) bool { return agentMinimumPatch(version, 28) }

// CertificateDeletionAgentCompatible gates the destructive certificate-file
// operation until nodes run an agent that validates and removes one cert tree.
func CertificateDeletionAgentCompatible(version string) bool { return agentMinimumPatch(version, 36) }
