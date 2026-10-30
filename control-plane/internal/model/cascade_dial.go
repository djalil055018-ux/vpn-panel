package model

import "net"

const CascadeDialMinimumAgent = "0.2.44"

func CascadeDialAgentCompatible(version string) bool { return agentMinimumPatch(version, 44) }

// Empty policy preserves the existing single-dial behavior. An explicit public
// or private unicast IPv4 pin is bounded; no hostname resolution occurs while
// compiling signed assignments, and no unauthenticated/direct fallback exists.
func ValidCascadeDial(ip string, attempts int) bool {
	if ip == "" && attempts == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil && parsed.IsGlobalUnicast() && parsed.String() == ip && attempts >= 2 && attempts <= 16
}
