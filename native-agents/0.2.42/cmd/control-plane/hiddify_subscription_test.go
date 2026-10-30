package main

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"vpn-platform/internal/subscriptioncompat"
)

func TestHiddifyPublicResponseAndInactiveAdmission(t *testing.T) {
	for _, status := range []string{"ACTIVE", "DISABLED", "EXPIRED", "LIMITED"} {
		fixture := publicSubscriptionFixture()
		fixture.Account.Status = status
		fixture.Hosts[0].Transport = "xhttp"
		fixture.Hosts[0].Security = "tls"
		fixture.Hosts[0].TransportOptions = subscriptioncompat.Options{"mode": "auto", "path": "/test/"}
		fixture.Hosts[0].SecurityOptions = subscriptioncompat.Options{"serverName": "example.test", "fingerprint": "chrome"}
		request := httptest.NewRequest("GET", "https://example.test/sub/synthetic", nil)
		request.Header.Set("User-Agent", "HiddifyNext/4.1.1 (android) like ClashMeta v2ray sing-box")
		response := httptest.NewRecorder()
		writeImportedSubscription(response, request, fixture)
		if response.Code != 200 || response.Header().Get("Remote-Dns-Address") != "https://1.1.1.1/dns-query" {
			t.Fatal("Hiddify response missing")
		}
		body, err := base64.StdEncoding.DecodeString(response.Body.String())
		if err != nil {
			t.Fatal(err)
		}
		if status != "ACTIVE" {
			if bytes.Contains(body, []byte(fixture.Credential)) || bytes.Contains(body, []byte(fixture.Hosts[0].Address)) {
				t.Fatal("inactive credentials exposed")
			}
			continue
		}
		uri, err := url.Parse(strings.TrimSpace(string(body)))
		if err != nil || uri.Query().Get("alpn") != "h2" || uri.User.Username() != fixture.Credential {
			t.Fatal("active subscription adaptation failed")
		}
	}
}
