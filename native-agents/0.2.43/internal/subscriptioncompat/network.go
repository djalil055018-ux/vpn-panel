package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// RenderClient keeps authorization and transport rendering in Render. Only
// the network policy of a generated Xray JSON response is adapted here.
func RenderClient(hosts []Host, template Options, format, credential string) ([]byte, error) {
	raw, err := Render(hosts, template, format, credential)
	if err != nil {
		return raw, err
	}
	if format != "XRAY_JSON" {
		return applyAutoStructured(raw, hosts, format)
	}
	var configs []Options
	if json.Unmarshal(raw, &configs) != nil {
		return nil, ErrProfile
	}
	index := 0
	for _, host := range hosts {
		if skipped(host, format) {
			continue
		}
		if index >= len(configs) {
			return nil, ErrProfile
		}
		applyTunnelDNS(configs[index], host.Address)
		applyAutoXray(configs[index], host)
		index++
	}
	if index != len(configs) {
		return nil, ErrProfile
	}
	return json.Marshal(configs)
}

func applyTunnelDNS(cfg Options, address string) {
	servers := []any{}
	if net.ParseIP(address) == nil {
		// Resolving the proxy itself through that proxy would create a loop.
		// Only its exact hostname uses direct DoH; app DNS stays in the VPN.
		for _, endpoint := range []string{"https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"} {
			servers = append(servers, Options{"address": endpoint, "domains": []string{"full:" + address}, "skipFallback": true})
		}
	}
	servers = append(servers, "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
	dns := Options{"servers": servers, "tag": "pauk-dns-query", "queryStrategy": "UseIPv4", "disableFallbackIfMatch": true}
	if hosts := object(cfg["dns"])["hosts"]; hosts != nil {
		dns["hosts"] = clone(hosts)
	}
	cfg["dns"] = dns
	outbounds := cfg["outbounds"].([]any)
	proxy := object(outbounds[0])
	stream := object(proxy["streamSettings"])
	sockopt := copyObject(object(stream["sockopt"]))
	sockopt["domainStrategy"] = "UseIPv4"
	stream["sockopt"] = sockopt
	// The namespace belongs to PAUK. Ignore an older copy when refreshing.
	retained := []any{}
	for _, out := range outbounds {
		if text(object(out)["tag"]) != "pauk-dns-out" {
			retained = append(retained, out)
		}
	}
	cfg["outbounds"] = append(retained, Options{"tag": "pauk-dns-out", "protocol": "dns", "settings": Options{}})
	routing := copyObject(object(cfg["routing"]))
	rules := []any{
		Options{"type": "field", "inboundTag": []string{"pauk-dns-query"}, "outboundTag": "proxy"},
		Options{"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "pauk-dns-out"},
	}
	if existing, ok := routing["rules"].([]any); ok {
		rules = append(rules, existing...)
	}
	routing["rules"] = rules
	cfg["routing"] = routing
}

// Application-specific headers configure DNS inside the client tunnel.
func SetClientNetworkHeaders(headers http.Header, userAgent string) {
	if isHiddify(userAgent) {
		headers.Set("Remote-Dns-Address", "https://1.1.1.1/dns-query")
		return
	}
	if !strings.HasPrefix(strings.ToLower(userAgent), "happ/") {
		return
	}
	profile := Options{
		"Name": "PAUK DNS", "GlobalProxy": "true", "RemoteDNSType": "DoH",
		"RemoteDNSDomain": "https://cloudflare-dns.com/dns-query", "RemoteDNSIP": "1.1.1.1",
		"DomesticDNSType": "DoH", "DomesticDNSDomain": "https://dns.google/dns-query", "DomesticDNSIP": "8.8.8.8",
		"DnsHosts": Options{"cloudflare-dns.com": "1.1.1.1", "dns.google": "8.8.8.8"},
		"Geoipurl": "", "Geositeurl": "", "DirectSites": []string{}, "DirectIp": []string{},
		"ProxySites": []string{}, "ProxyIp": []string{}, "BlockSites": []string{}, "BlockIp": []string{},
		"DomainStrategy": "AsIs", "FakeDNS": "false",
	}
	raw, _ := json.Marshal(profile)
	headers.Set("Routing", "happ://routing/onadd/"+base64.StdEncoding.EncodeToString(raw))
}
