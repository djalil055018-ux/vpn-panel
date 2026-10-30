package subscriptioncompat

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestHiddifyKeepsEveryProfileAndCredential(t *testing.T) {
	lines := []string{
		"vless://synthetic@vpn.example:443?type=xhttp&security=tls&path=%2Ftest%2F&mode=auto#Flag%20name",
		"vless://synthetic@vpn.example:443?type=xhttp&security=tls&alpn=http%2F1.1#explicit",
		"vless://synthetic@vpn.example:443?type=tcp&security=reality&pbk=public&sid=01#reality",
		"vless://synthetic@vpn.example:443?type=grpc&security=tls&serviceName=test#grpc",
		"trojan://synthetic@vpn.example:443?security=tls#trojan",
		"hysteria2://synthetic@vpn.example:443?sni=vpn.example#hy2",
		"",
	}
	raw := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))))
	for _, ua := range []string{"Hiddify/4.1.1", "hiddify/4.0.4", "HiddifyNext/4.1.1 (android) like ClashMeta v2ray sing-box", "HiddifyNextX/4.1.1 (android) like ClashMeta v2ray sing-box", "INCY/3.7.0", "Happ/3.0", "WPS/16.4.8", "curl/8", "Mozilla/5.0"} {
		got, err := AdaptHiddifySubscription(raw, "XRAY_BASE64", ua)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(strings.ToLower(ua), "hiddify") {
			if !bytes.Equal(got, raw) {
				t.Fatal("other client changed")
			}
			continue
		}
		body, err := base64.StdEncoding.DecodeString(string(got))
		if err != nil {
			t.Fatal(err)
		}
		result := strings.Split(string(body), "\n")
		if len(result) != len(lines) || !reflect.DeepEqual(result[1:], lines[1:]) {
			t.Fatal("profiles changed or removed")
		}
		before, _ := url.Parse(lines[0])
		after, _ := url.Parse(result[0])
		query := after.Query()
		if query.Get("alpn") != "h2" {
			t.Fatal("XHTTP HTTP/2 missing")
		}
		query.Del("alpn")
		if !reflect.DeepEqual(query, before.Query()) || before.User.String() != after.User.String() || before.Host != after.Host || before.Fragment != after.Fragment {
			t.Fatal("profile identity or other options changed")
		}
		again, err := AdaptHiddifySubscription(got, "XRAY_BASE64", ua)
		if err != nil || !bytes.Equal(again, got) {
			t.Fatal("adaptation not idempotent")
		}
	}
}

func TestHiddifyDNSHeaderAndFormatBoundary(t *testing.T) {
	for _, ua := range []string{"Hiddify/4.1.1", "HiddifyNext/4.1.1 (android) like ClashMeta v2ray sing-box", "HiddifyNextX/4.1.1 (android) like ClashMeta v2ray sing-box", "HiddifyNextInvalid/1.0", "Happ/3.0", "INCY/3.7.0", "WPS/16.4.8", "Mozilla/5.0"} {
		headers := http.Header{}
		SetClientNetworkHeaders(headers, ua)
		want := strings.HasPrefix(ua, "Hiddify/") || strings.HasPrefix(ua, "HiddifyNext/") || strings.HasPrefix(ua, "HiddifyNextX/")
		if (headers.Get("Remote-Dns-Address") == "https://1.1.1.1/dns-query") != want {
			t.Fatal("DNS header scope")
		}
	}
	for _, format := range []string{"XRAY_JSON", "SINGBOX", "MIHOMO", "CLASH", "STASH"} {
		raw := []byte("unchanged structured response")
		got, err := AdaptHiddifySubscription(raw, format, "Hiddify/4.1.1")
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatal("structured format changed")
		}
	}
	if _, err := AdaptHiddifySubscription([]byte("invalid!"), "XRAY_BASE64", "Hiddify/4.1.1"); err == nil {
		t.Fatal("bad subscription accepted")
	}
}
