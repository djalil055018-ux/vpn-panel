package subscriptioncompat

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ptr[T any](value T) *T { return &value }
func policyFixture() Policy {
	p := Policy{Rules: ResponseRules{Version: "1", Rules: []ResponseRule{
		{Name: "browser", Enabled: ptr(true), Operator: "AND", Response: "BROWSER", Conditions: []ResponseCondition{{Header: "accept", Operator: "CONTAINS", Value: "text/html", CaseSensitive: ptr(true)}}},
		{Name: "mihomo", Enabled: ptr(true), Operator: "AND", Response: "MIHOMO", Conditions: []ResponseCondition{{Header: "user-agent", Operator: "REGEX", Value: "^mihomo|^clash-meta", CaseSensitive: ptr(false)}}},
		{Name: "fallback", Enabled: ptr(true), Operator: "AND", Response: "XRAY_BASE64", Conditions: []ResponseCondition{}},
	}}, Headers: map[string]string{"profile-title": "rwEncodeBase64:Общий профиль", "profile-web-page-url": "{{SUBSCRIPTION_URL}}", "announce": "rwEncodeBase64:Информация", "support-url": "https://support.example.test"},
		Remarks: map[string][]string{}, ShowRemarks: true, ServeJSON: true, HWID: HWIDPolicy{Enabled: ptr(false), Fallback: ptr(2)}}
	for _, key := range []string{"HWIDMaxDevicesExceeded", "HWIDNotSupported", "disabledUsers", "emptyHosts", "expiredUsers", "limitedUsers"} {
		p.Remarks[key] = []string{key}
	}
	return p
}
func TestSubscriptionPolicySelection(t *testing.T) {
	p := policyFixture()
	cases := []struct{ ua, accept, path, want string }{
		{"", "", "", "BLOCK"}, {"", "text/html", "json", "BLOCK"},
		{"Mihomo/1", "", "", "MIHOMO"}, {"Clash-Meta/1", "", "", "MIHOMO"},
		{"Mihomo/1", "text/html", "", "BROWSER"}, {"Mihomo/1", "TEXT/HTML", "", "MIHOMO"},
		{"Happ/1", "", "", "XRAY_JSON"}, {"happ/1", "", "", "XRAY_BASE64"},
		{"v2rayNG/1.8.9", "", "", "XRAY_JSON"}, {"v2rayNG/unknown", "", "", "XRAY_BASE64"},
		{"Streisand", "", "", "XRAY_JSON"}, {"Curl", "", "", "XRAY_BASE64"},
		{"Happ/1", "text/html", "stash", "STASH"}, {"Curl", "", "json", "XRAY_JSON"},
		{"Curl", "", "v2ray-json", "XRAY_JSON"}, {"Curl", "", "singbox", "SINGBOX"},
		{"Curl", "", "clash", "CLASH"}, {"Curl", "", "mihomo", "MIHOMO"},
		{"Curl", "", "xray-json", "BLOCK"}, {"Curl", "", "JSON", "BLOCK"},
	}
	for _, c := range cases {
		got, err := p.Select(http.Header{"user-agent": []string{c.ua}, "accept": []string{c.accept}}, c.path)
		if err != nil || got.Format != c.want {
			t.Fatalf("selection %q/%q/%q: %v %s", c.ua, c.accept, c.path, err, got.Format)
		}
	}
	p.Rules.Settings.DisablePath = true
	got, err := p.Select(http.Header{"User-Agent": []string{"Mihomo"}}, "json")
	if err != nil || got.Format != "BLOCK" {
		t.Fatal("disabled explicit path")
	}
	p.Rules.Settings.DisablePath = false
	p.ServeJSON = false
	got, err = p.Select(http.Header{"User-Agent": []string{"Happ/1"}}, "")
	if err != nil || got.Format != "XRAY_BASE64" {
		t.Fatal("serve JSON setting")
	}
}
func TestSubscriptionPolicyConditions(t *testing.T) {
	for _, op := range []string{"EQUALS", "NOT_EQUALS", "CONTAINS", "NOT_CONTAINS", "STARTS_WITH", "NOT_STARTS_WITH", "ENDS_WITH", "NOT_ENDS_WITH", "REGEX", "NOT_REGEX"} {
		c := ResponseCondition{Header: "X-Test", Operator: op, Value: "needle", CaseSensitive: ptr(false)}
		if c.matches(http.Header{}) {
			t.Fatal("missing negative header matched")
		}
		found := c.matches(http.Header{"X-Test": []string{"NEEDLE"}})
		if found == strings.HasPrefix(op, "NOT_") {
			t.Fatalf("operator %s", op)
		}
	}
	c := ResponseCondition{Header: "x-test", Operator: "EQUALS", Value: "a,b", CaseSensitive: ptr(true)}
	if !c.matches(http.Header{"X-Test": []string{"a", "b"}}) {
		t.Fatal("array header join")
	}
	p := policyFixture()
	p.Rules.Rules[0].Operator = "OR"
	p.Rules.Rules[0].Conditions = append(p.Rules.Rules[0].Conditions, ResponseCondition{Header: "X-Test", Operator: "EQUALS", Value: "yes", CaseSensitive: ptr(true)})
	got, err := p.Select(http.Header{"User-Agent": []string{"curl"}, "X-Test": []string{"yes"}}, "")
	if err != nil || got.Format != "BROWSER" {
		t.Fatal("OR matching")
	}
	p.Rules.Rules[0].Conditions = []ResponseCondition{}
	got, err = p.Select(http.Header{"User-Agent": []string{"curl"}}, "")
	if err != nil || got.Format != "BROWSER" {
		t.Fatal("empty OR source behavior")
	}
}
func TestSubscriptionPolicyAccountIsolation(t *testing.T) {
	p := policyFixture()
	a := ResponseAccount{Username: "synthetic-user", SubscriptionURL: "https://sub.example.test/synthetic-alias", UsedBytes: 123, LimitBytes: 456, ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
	remove := []string{"profile-title", "profile-web-page-url", "announce"}
	external, err := p.OverlayExternal(remove, map[string]string{"profile-title": "rwEncodeBase64:Другой профиль"}, map[string][]string{"HWIDMaxDevicesExceeded": {}, "HWIDNotSupported": {}, "disabledUsers": {"blocked"}, "emptyHosts": {}, "expiredUsers": {"expired"}, "limitedUsers": {}}, &HWIDPolicy{Enabled: ptr(false), Fallback: ptr(9999)}, ptr("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	if err != nil {
		t.Fatal("overlay")
	}
	h, err := external.ResponseHeaders(a)
	if err != nil || h.Get("Profile-Web-Page-Url") != "" || h.Get("Announce") != "" || h.Get("Profile-Title") != "base64:"+base64.StdEncoding.EncodeToString([]byte("Другой профиль")) || h.Get("Subscription-Userinfo") != "upload=0; download=123; total=456; expire=0" {
		t.Fatal("external response")
	}
	global, err := p.ResponseHeaders(a)
	if err != nil || global.Get("Profile-Web-Page-Url") != a.SubscriptionURL || global.Get("Announce") == "" || global.Get("Profile-Title") == h.Get("Profile-Title") || *p.HWID.Fallback != 2 || p.PageID != nil {
		t.Fatal("cross-account policy leaked")
	}
	external.Headers["support-url"] = "https://changed.example.test"
	external.Remarks["expiredUsers"][0] = "changed"
	if p.Headers["support-url"] != "https://support.example.test" || p.Remarks["expiredUsers"][0] != "expiredUsers" {
		t.Fatal("overlay aliases original")
	}
	for status, key := range map[string]string{"EXPIRED": "expiredUsers", "DISABLED": "disabledUsers", "LIMITED": "limitedUsers", "ACTIVE": "emptyHosts"} {
		notice, err := p.Notice(status, 0, a.SubscriptionURL)
		if err != nil || !reflect.DeepEqual(notice, p.Remarks[key]) {
			t.Fatal("account notice")
		}
	}
	notice, err := p.Notice("ACTIVE", 2, a.SubscriptionURL)
	if err != nil || notice != nil {
		t.Fatal("active response has notice")
	}
	a.ExpiresAt = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	h, err = p.ResponseHeaders(a)
	if err != nil || strings.HasSuffix(h.Get("Subscription-Userinfo"), "expire=0") {
		t.Fatal("expiry lost")
	}
}
func TestSubscriptionPolicyRejectUnsupported(t *testing.T) {
	tests := map[string]func(*Policy){
		"HWID enable":          func(p *Policy) { p.HWID.Enabled = ptr(true) },
		"missing HWID":         func(p *Policy) { p.HWID.Enabled = nil },
		"missing fallback":     func(p *Policy) { p.HWID.Fallback = nil },
		"unknown header":       func(p *Policy) { p.Headers["set-cookie"] = "x=1" },
		"header newline":       func(p *Policy) { p.Headers["announce"] = "hello\r\ninjected: true" },
		"unsupported variable": func(p *Policy) { p.Headers["announce"] = "{{STATUS}}" },
		"invalid regex":        func(p *Policy) { p.Rules.Rules[1].Conditions[0].Value = "[" },
		"unsupported regex":    func(p *Policy) { p.Rules.Rules[1].Conditions[0].Value = "(?=x)x" },
		"missing enabled":      func(p *Policy) { p.Rules.Rules[0].Enabled = nil },
		"response mods":        func(p *Policy) { p.Rules.Rules[0].Modifications = Options{"encryption": true} },
		"unknown response":     func(p *Policy) { p.Rules.Rules[0].Response = "HTTP_REDIRECT" },
		"missing case":         func(p *Policy) { p.Rules.Rules[0].Conditions[0].CaseSensitive = nil },
		"missing remarks":      func(p *Policy) { delete(p.Remarks, "expiredUsers") },
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			p := policyFixture()
			modify(&p)
			if p.Validate() != ErrProfile {
				t.Fatal("unsupported policy accepted")
			}
		})
	}
	p := policyFixture()
	a := ResponseAccount{Username: "user\r\nInjected: yes", SubscriptionURL: "https://sub.example.test/alias", ExpiresAt: time.Now()}
	if _, err := p.ResponseHeaders(a); err != ErrProfile {
		t.Fatal("header injection")
	}
	if _, err := p.Select(http.Header{"User-Agent": []string{"curl\nInjected: yes"}}, ""); err != ErrProfile {
		t.Fatal("request injection")
	}
}
