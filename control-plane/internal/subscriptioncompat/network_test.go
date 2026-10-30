package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestTunnelDNSPreservesTransportAndRoutes(t *testing.T) {
	cfg := Options{
		"dns":       Options{"hosts": Options{"blocked.example": "127.0.0.1"}},
		"outbounds": []any{Options{"tag": "proxy", "protocol": "vless", "settings": Options{"vnext": []any{Options{"address": "vpn.example", "port": 443}}}, "streamSettings": Options{"security": "reality", "network": "tcp", "realitySettings": Options{"serverName": "test.example", "fingerprint": "firefox"}}}, Options{"tag": "direct", "protocol": "freedom"}},
		"routing":   Options{"domainStrategy": "IPIfNonMatch", "rules": []any{Options{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"}}},
	}
	cfg = copyObject(cfg)
	before := copyObject(cfg)
	applyTunnelDNS(cfg, "vpn.example")
	proxy := object(cfg["outbounds"].([]any)[0])
	old := object(before["outbounds"].([]any)[0])
	if !reflect.DeepEqual(proxy["settings"], old["settings"]) {
		t.Fatal("credentials or destination changed")
	}
	stream := copyObject(object(proxy["streamSettings"]))
	delete(stream, "sockopt")
	if !reflect.DeepEqual(stream, old["streamSettings"]) {
		t.Fatal("transport changed")
	}
	dns := object(cfg["dns"])
	if !reflect.DeepEqual(dns["hosts"], object(before["dns"])["hosts"]) {
		t.Fatal("DNS host overrides lost")
	}
	servers := dns["servers"].([]any)
	if len(servers) != 4 || object(servers[0])["skipFallback"] != true || !reflect.DeepEqual(object(servers[0])["domains"], []string{"full:vpn.example"}) {
		t.Fatal("proxy bootstrap not isolated")
	}
	if servers[2] != "https://1.1.1.1/dns-query" || servers[3] != "https://8.8.8.8/dns-query" {
		t.Fatal("app DNS is not DoH")
	}
	rules := object(cfg["routing"])["rules"].([]any)
	if len(rules) != 3 || object(rules[0])["outboundTag"] != "proxy" || object(rules[1])["outboundTag"] != "pauk-dns-out" {
		t.Fatal("DNS interception precedence broken")
	}
	if !reflect.DeepEqual(rules[2], object(before["routing"])["rules"].([]any)[0]) {
		t.Fatal("existing route removed")
	}
}

func TestTunnelDNSIPNeedsNoDirectBootstrap(t *testing.T) {
	cfg := Options{"outbounds": []any{Options{"tag": "proxy", "streamSettings": Options{}}}}
	applyTunnelDNS(cfg, "203.0.113.12")
	if len(object(cfg["dns"])["servers"].([]any)) != 2 {
		t.Fatal("unnecessary direct DNS")
	}
}

func TestHappTunnelHeaderOnlyHapp(t *testing.T) {
	for _, ua := range []string{"Happ/3.0.0", "happ/1.0", "INCY/3.7.0", "WPS/16.4.8", "Hiddify/4.0.4", "Mozilla/5.0"} {
		h := http.Header{}
		SetClientNetworkHeaders(h, ua)
		isHapp := strings.HasPrefix(strings.ToLower(ua), "happ/")
		if (h.Get("Routing") != "") != isHapp {
			t.Fatal("wrong client targeted")
		}
		if !isHapp {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h.Get("Routing"), "happ://routing/onadd/"))
		var p Options
		if err != nil || json.Unmarshal(raw, &p) != nil || p["RemoteDNSType"] != "DoH" || p["RemoteDNSIP"] != "1.1.1.1" || p["GlobalProxy"] != "true" {
			t.Fatal("invalid Happ routing profile")
		}
	}
}
