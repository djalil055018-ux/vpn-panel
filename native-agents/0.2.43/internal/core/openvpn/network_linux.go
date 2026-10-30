//go:build linux

package openvpn

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

type networkRule struct {
	binary, table, chain string
	args                 []string
}

func networkRules() []networkRule {
	rules := []networkRule{{"iptables", "filter", "VP_OVPN_IN", []string{"-j", "DROP"}}}
	for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		rules = append(rules, networkRule{"iptables", "filter", "VP_OVPN_OUT", []string{"-d", cidr, "-j", "DROP"}})
	}
	rules = append(rules, networkRule{"iptables", "filter", "VP_OVPN_OUT", []string{"-s", "10.77.0.0/24", "-j", "ACCEPT"}}, networkRule{"iptables", "filter", "VP_OVPN_OUT", []string{"-j", "DROP"}}, networkRule{"iptables", "filter", "VP_OVPN_BACK", []string{"-d", "10.77.0.0/24", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}, networkRule{"iptables", "filter", "VP_OVPN_BACK", []string{"-j", "DROP"}}, networkRule{"iptables", "nat", "VP_OVPN_NAT", []string{"-s", "10.77.0.0/24", "!", "-o", "vpnovpn0", "-j", "MASQUERADE"}}, networkRule{"ip6tables", "filter", "VP_OVPN_V6", []string{"-j", "DROP"}})
	return rules
}
func networkJumps() []networkRule {
	return []networkRule{
		{"iptables", "filter", "INPUT", []string{"-i", "vpnovpn0", "-j", "VP_OVPN_IN"}},
		{"iptables", "filter", "FORWARD", []string{"-i", "vpnovpn0", "-j", "VP_OVPN_OUT"}},
		{"iptables", "filter", "FORWARD", []string{"-o", "vpnovpn0", "-j", "VP_OVPN_BACK"}},
		{"iptables", "nat", "POSTROUTING", []string{"-s", "10.77.0.0/24", "-j", "VP_OVPN_NAT"}},
		{"ip6tables", "filter", "INPUT", []string{"-i", "vpnovpn0", "-j", "VP_OVPN_V6"}},
		{"ip6tables", "filter", "FORWARD", []string{"-i", "vpnovpn0", "-j", "VP_OVPN_V6"}},
		{"ip6tables", "filter", "FORWARD", []string{"-o", "vpnovpn0", "-j", "VP_OVPN_V6"}},
	}
}
func firewall(ctx context.Context, r networkRule, op string) error {
	args := []string{"-w", "3", "-t", r.table, op, r.chain}
	args = append(args, r.args...)
	return exec.CommandContext(ctx, "/usr/sbin/"+r.binary, args...).Run()
}
func VerifyNetwork(ctx context.Context) error {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(raw)) != "1" {
		return ErrRuntime
	}
	for _, r := range append(networkRules(), networkJumps()...) {
		if firewall(ctx, r, "-C") != nil {
			return ErrRuntime
		}
	}
	return nil
}

// Only our dedicated chains are created, never flushed. If an interrupted
// preparation left a partial chain, require repair instead of broadening access.
// IPv4 forwarding is enabled only after both the tunnel isolation and NAT rules.
func PrepareNetwork(ctx context.Context) error {
	groups := map[string][]networkRule{}
	order := []string{}
	for _, r := range networkRules() {
		key := r.binary + "/" + r.table + "/" + r.chain
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], r)
	}
	for _, key := range order {
		rules := groups[key]
		head := rules[0]
		head.args = nil
		exists := firewall(ctx, head, "-S") == nil
		if !exists {
			if firewall(ctx, head, "-N") != nil {
				return ErrRuntime
			}
			for _, r := range rules {
				if firewall(ctx, r, "-A") != nil {
					return ErrRuntime
				}
			}
		} else {
			for _, r := range rules {
				if firewall(ctx, r, "-C") != nil {
					return ErrRuntime
				}
			}
		}
	}
	for _, r := range networkJumps() {
		if firewall(ctx, r, "-C") != nil {
			if firewall(ctx, r, "-I") != nil {
				return ErrRuntime
			}
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		return ErrRuntime
	}
	return VerifyNetwork(ctx)
}
