//go:build linux

package pptp

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

type networkRule struct {
	binary, table, chain string
	args                 []string
}

func networkRules() []networkRule {
	rules := []networkRule{{"iptables", "filter", "VP_PPTP_IN", []string{"-j", "DROP"}}}
	for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		rules = append(rules, networkRule{"iptables", "filter", "VP_PPTP_OUT", []string{"-d", cidr, "-j", "DROP"}})
	}
	rules = append(rules, networkRule{"iptables", "filter", "VP_PPTP_OUT", []string{"-s", "10.78.0.0/24", "-j", "ACCEPT"}}, networkRule{"iptables", "filter", "VP_PPTP_OUT", []string{"-j", "DROP"}}, networkRule{"iptables", "filter", "VP_PPTP_BACK", []string{"-d", "10.78.0.0/24", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}, networkRule{"iptables", "filter", "VP_PPTP_BACK", []string{"-j", "DROP"}}, networkRule{"iptables", "nat", "VP_PPTP_NAT", []string{"-s", "10.78.0.0/24", "!", "-o", "vppptp+", "-j", "MASQUERADE"}}, networkRule{"ip6tables", "filter", "VP_PPTP_V6", []string{"-j", "DROP"}})
	return rules
}
func networkJumps() []networkRule {
	return []networkRule{
		{"iptables", "filter", "INPUT", []string{"-i", "vppptp+", "-j", "VP_PPTP_IN"}},
		{"iptables", "filter", "FORWARD", []string{"-i", "vppptp+", "-j", "VP_PPTP_OUT"}},
		{"iptables", "filter", "FORWARD", []string{"-o", "vppptp+", "-j", "VP_PPTP_BACK"}},
		{"iptables", "nat", "POSTROUTING", []string{"-s", "10.78.0.0/24", "-j", "VP_PPTP_NAT"}},
		{"ip6tables", "filter", "INPUT", []string{"-i", "vppptp+", "-j", "VP_PPTP_V6"}},
		{"ip6tables", "filter", "FORWARD", []string{"-i", "vppptp+", "-j", "VP_PPTP_V6"}},
		{"ip6tables", "filter", "FORWARD", []string{"-o", "vppptp+", "-j", "VP_PPTP_V6"}},
	}
}
func firewall(ctx context.Context, r networkRule, op string) error {
	args := []string{"-w", "3", "-t", r.table, op, r.chain}
	args = append(args, r.args...)
	return exec.CommandContext(ctx, "/usr/sbin/"+r.binary, args...).Run()
}
func VerifyNetwork(ctx context.Context) error {
	if err := verifyKernelAndPool(); err != nil {
		return err
	}
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(raw)) != "1" {
		return ErrRuntime
	}
	for _, r := range append(networkRules(), networkJumps()...) {
		if firewall(ctx, r, "-C") != nil {
			return ErrRuntime
		}
	}
	if err := verifyRuleOrder(ctx); err != nil {
		return err
	}
	return nil
}

// Only our dedicated chains are created, never flushed. If an interrupted
// preparation left a partial chain, require repair instead of broadening access.
// IPv4 forwarding is enabled only after both the tunnel isolation and NAT rules.
func PrepareNetwork(ctx context.Context) error {
	for _, name := range []string{"pptp", "ppp_mppe"} {
		if _, err := os.Stat("/sys/module/" + name); os.IsNotExist(err) {
			if err = exec.CommandContext(ctx, "modprobe", name).Run(); err != nil {
				return ErrRuntime
			}
		}
	}
	if _, err := os.Lstat("/dev/ppp"); os.IsNotExist(err) {
		if err = syscall.Mknod("/dev/ppp", syscall.S_IFCHR|0600, 108<<8); err != nil {
			return ErrRuntime
		}
	}
	if err := verifyKernelAndPool(); err != nil {
		return err
	}
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

func verifyKernelAndPool() error {
	for _, name := range []string{"pptp", "ppp_mppe"} {
		if _, err := os.Stat("/sys/module/" + name); err != nil {
			return ErrRuntime
		}
	}
	i, err := os.Lstat("/dev/ppp")
	if err != nil || i.Mode()&os.ModeCharDevice == 0 {
		return ErrRuntime
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Rdev != 108<<8 {
		return ErrRuntime
	}
	_, pool, _ := net.ParseCIDR("10.78.0.0/24")
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "vppptp") {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			ip, subnet, err := net.ParseCIDR(address.String())
			if err == nil && (pool.Contains(ip) || subnet.Contains(pool.IP)) {
				return ErrRuntime
			}
		}
	}
	return nil
}

// Required rules must also have their original order. Merely finding them with
// -C would miss an ACCEPT rule inserted ahead of the isolation boundary.
func canonicalRule(value string) string {
	return strings.ReplaceAll(strings.Join(strings.Fields(value), " "), "ESTABLISHED,RELATED", "RELATED,ESTABLISHED")
}
func verifyRuleOrder(ctx context.Context) error {
	groups := map[string][]networkRule{}
	for _, r := range networkRules() {
		key := r.binary + "/" + r.table + "/" + r.chain
		groups[key] = append(groups[key], r)
	}
	for _, group := range groups {
		r := group[0]
		raw, err := exec.CommandContext(ctx, "/usr/sbin/"+r.binary, "-w", "3", "-t", r.table, "-S", r.chain).Output()
		if err != nil {
			return ErrRuntime
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) != len(group)+1 || canonicalRule(lines[0]) != "-N "+r.chain {
			return ErrRuntime
		}
		for i, want := range group {
			if canonicalRule(lines[i+1]) != canonicalRule("-A "+want.chain+" "+strings.Join(want.args, " ")) {
				return ErrRuntime
			}
		}
	}
	groups = map[string][]networkRule{}
	for _, r := range networkJumps() {
		key := r.binary + "/" + r.table + "/" + r.chain
		groups[key] = append([]networkRule{r}, groups[key]...)
	}
	for _, group := range groups {
		r := group[0]
		raw, err := exec.CommandContext(ctx, "/usr/sbin/"+r.binary, "-w", "3", "-t", r.table, "-S", r.chain).Output()
		if err != nil {
			return ErrRuntime
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) < len(group)+1 {
			return ErrRuntime
		}
		for i, want := range group {
			if canonicalRule(lines[i+1]) != canonicalRule("-A "+want.chain+" "+strings.Join(want.args, " ")) {
				return ErrRuntime
			}
		}
	}
	return nil
}
