package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

func publicSubscriptionFixture() store.ImportedSubscriptionSnapshot {
	yes, no := true, false
	limit := 2
	p := subscriptioncompat.Policy{ShowRemarks: true, ServeJSON: true, HWID: subscriptioncompat.HWIDPolicy{Enabled: &no, Fallback: &limit},
		Headers: map[string]string{"profile-web-page-url": "{{SUBSCRIPTION_URL}}"}, Remarks: map[string][]string{},
		Rules: subscriptioncompat.ResponseRules{Version: "1", Rules: []subscriptioncompat.ResponseRule{
			{Name: "browser", Enabled: &yes, Operator: "AND", Response: "BROWSER", Conditions: []subscriptioncompat.ResponseCondition{{Header: "accept", Operator: "CONTAINS", Value: "text/html", CaseSensitive: &yes}}},
			{Name: "fallback", Enabled: &yes, Operator: "AND", Response: "XRAY_BASE64", Conditions: []subscriptioncompat.ResponseCondition{}},
		}}}
	for _, key := range []string{"HWIDMaxDevicesExceeded", "HWIDNotSupported", "disabledUsers", "emptyHosts", "expiredUsers", "limitedUsers"} {
		p.Remarks[key] = []string{key}
	}
	h := subscriptioncompat.Host{Name: "Synthetic", Address: "endpoint.example.test", Port: 443, Protocol: "vless", Transport: "tcp", Security: "reality",
		ProtocolOptions: subscriptioncompat.Options{"encryption": "none", "flow": ""}, SecurityOptions: subscriptioncompat.Options{"serverName": "example.test", "publicKey": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "fingerprint": "firefox"}}
	out := store.ImportedSubscriptionSnapshot{Credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Hosts: []subscriptioncompat.Host{h}, Policy: p,
		Account:   subscriptioncompat.ResponseAccount{Alias: "synthetic-subscription", Username: "synthetic", SubscriptionURL: "https://source.example.test/synthetic-subscription", UsedBytes: 123, LifetimeBytes: 456, LimitBytes: 1000, ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), Status: "ACTIVE"},
		Templates: map[string]subscriptioncompat.Template{}}
	for _, format := range []string{"XRAY_JSON", "SINGBOX", "MIHOMO", "STASH", "CLASH"} {
		out.Templates[format] = subscriptioncompat.Template{Format: format, Body: subscriptioncompat.Options{}}
	}
	return out
}
func TestSubscriptionPublicHTTPFormatsAndInactiveAccounts(t *testing.T) {
	for _, status := range []string{"ACTIVE", "DISABLED", "EXPIRED", "LIMITED"} {
		for _, format := range []string{"", "json", "singbox", "mihomo", "stash", "clash", "browser"} {
			snapshot := publicSubscriptionFixture()
			snapshot.Account.Status = status
			req := httptest.NewRequest("GET", "https://attacker.example.test/ignored?credential=attacker", nil)
			req.Header.Set("User-Agent", "curl/8")
			if format == "browser" {
				req.Header.Set("Accept", "text/html")
			} else {
				req.SetPathValue("format", format)
			}
			res := httptest.NewRecorder()
			writeImportedSubscription(res, req, snapshot)
			if res.Code != 200 || res.Header().Get("Cache-Control") != "no-store" || res.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("response %s/%s code %d", status, format, res.Code)
			}
			body := res.Body.Bytes()
			if format == "" {
				var err error
				body, err = base64.StdEncoding.DecodeString(string(body))
				if err != nil {
					t.Fatal("base64 response")
				}
			} else if !json.Valid(body) {
				t.Fatal("structured response")
			}
			if bytes.Contains(body, []byte("attacker")) {
				t.Fatal("request controls public identity")
			}
			wantCredential := status == "ACTIVE" && format != "clash"
			if bytes.Contains(body, []byte(snapshot.Credential)) != wantCredential {
				t.Fatalf("credential %s/%s", status, format)
			}
			if status != "ACTIVE" && bytes.Contains(body, []byte("endpoint.example.test")) {
				t.Fatal("inactive endpoint")
			}
			if format != "browser" && res.Header().Get("Profile-Web-Page-Url") != snapshot.Account.SubscriptionURL {
				t.Fatal("canonical URL")
			}
		}
	}
}
func TestSubscriptionPublicHTTPDenialsAndHead(t *testing.T) {
	for _, kind := range []string{"missing-agent", "unknown-format", "unsupported-template", "head", "missing-credential", "block", "legal"} {
		snapshot := publicSubscriptionFixture()
		req := httptest.NewRequest("GET", "https://synthetic.example.test/", nil)
		req.Header.Set("User-Agent", "curl/8")
		want := 404
		switch kind {
		case "missing-agent":
			req.Header.Del("User-Agent")
		case "unknown-format":
			req.SetPathValue("format", "invalid")
		case "unsupported-template":
			req.SetPathValue("format", "json")
			delete(snapshot.Templates, "XRAY_JSON")
			want = 503
		case "head":
			req.Method = "HEAD"
			want = 200
		case "missing-credential":
			snapshot.Credential = ""
			want = 503
		case "block":
			snapshot.Policy.Rules.Rules[1].Response = "BLOCK"
		case "legal":
			snapshot.Policy.Rules.Rules[1].Response = "STATUS_CODE_451"
			want = 451
		}
		res := httptest.NewRecorder()
		writeImportedSubscription(res, req, snapshot)
		if res.Code != want || res.Header().Get("Cache-Control") != "no-store" || strings.Contains(res.Body.String(), snapshot.Hosts[0].Address) {
			t.Fatal("denial " + kind)
		}
		if kind == "head" && res.Body.Len() != 0 {
			t.Fatal("HEAD body")
		}
	}
	app := &application{}
	mux := http.NewServeMux()
	app.registerImportedSubscriptionRoutes(mux)
	for _, alias := range []string{"short", strings.Repeat("a", 129), "bad@subscription-alias"} {
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, httptest.NewRequest("GET", "/api/v1/public/imported-subscriptions/"+alias, nil))
		if res.Code != 404 || res.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("alias validation before store")
		}
	}
}
