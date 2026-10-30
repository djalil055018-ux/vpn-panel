package subscriptioncompat

import (
	"net"
	"vpn-platform/internal/model"
)

// Only native store metadata can enable this opt-in policy. It changes the TCP
// dial strategy, retaining the original credential, SNI and route selection.
func applyEndpointDialXray(cfg Options, h Host) error {
	if !model.ValidCascadeDial(h.ConnectRaceIP, h.ConnectRaceAttempts) {
		return ErrProfile
	}
	if h.ConnectRaceAttempts == 0 {
		return nil
	}
	if (h.Protocol != "vless" && h.Protocol != "trojan") || (h.Security != "tls" && h.Security != "reality") {
		return ErrProfile
	}
	switch h.Transport {
	case "tcp", "ws", "grpc", "xhttp":
	default:
		return ErrProfile
	}
	outbounds, ok := cfg["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return ErrProfile
	}
	proxy := object(outbounds[0])
	stream := object(proxy["streamSettings"])
	if stream == nil {
		return ErrProfile
	}
	address := h.Address
	if net.ParseIP(address) != nil {
		address = "pauk-endpoint-dial.invalid"
		settings := object(proxy["settings"])
		key := "vnext"
		if h.Protocol == "trojan" {
			key = "servers"
		}
		servers, ok := settings[key].([]any)
		if !ok || len(servers) != 1 {
			return ErrProfile
		}
		server := object(servers[0])
		if server == nil {
			return ErrProfile
		}
		server["address"] = address
	}
	dns := object(cfg["dns"])
	if dns == nil {
		return ErrProfile
	}
	if dns["hosts"] != nil && object(dns["hosts"]) == nil {
		return ErrProfile
	}
	hosts := copyObject(object(dns["hosts"]))
	delete(hosts, h.Address)
	delete(hosts, "full:"+h.Address)
	ips := make([]string, h.ConnectRaceAttempts)
	for i := range ips {
		ips[i] = h.ConnectRaceIP
	}
	hosts["full:"+address] = ips
	dns["hosts"] = hosts
	sockopt := copyObject(object(stream["sockopt"]))
	sockopt["domainStrategy"] = "ForceIPv4"
	sockopt["happyEyeballs"] = Options{"tryDelayMs": 100, "maxConcurrentTry": h.ConnectRaceAttempts, "interleave": 1}
	stream["sockopt"] = sockopt
	return nil
}
