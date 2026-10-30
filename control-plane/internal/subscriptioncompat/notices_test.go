package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestSubscriptionNoticesCannotGrantAccess(t *testing.T) {
	lines := []string{"Срок подписки истёк & #", ""}
	for _, format := range []string{"XRAY_BASE64", "XRAY_JSON", "MIHOMO", "SINGBOX", "STASH", "CLASH"} {
		t.Run(format, func(t *testing.T) {
			wire, err := RenderNotices(lines, Options{}, format)
			if err != nil {
				t.Fatal("notice render")
			}
			if format == "XRAY_BASE64" {
				raw, err := base64.StdEncoding.DecodeString(string(wire))
				if err != nil {
					t.Fatal("decode notice")
				}
				links := strings.Split(string(raw), "\n")
				if len(links) != len(lines) {
					t.Fatal("notice count")
				}
				for i, link := range links {
					u, err := url.Parse(link)
					if err != nil || u.Host != "0.0.0.0:1" || u.User.Username() != noticeCredential || u.Fragment != lines[i] {
						t.Fatal("notice endpoint, credential or remark")
					}
				}
			} else if !json.Valid(wire) {
				t.Fatal("invalid notice document")
			}
		})
	}
	for _, line := range []string{"bad\nremark", "{\"finalRemark\":\"custom profile\"}", "\t{\"f\":1}"} {
		if _, err := RenderNotices([]string{line}, Options{}, "XRAY_JSON"); err != ErrProfile {
			t.Fatal("unsafe notice accepted")
		}
	}
	h := testHost("tcp")
	h.Security = "none"
	if _, err := Render([]Host{h}, Options{}, "XRAY_JSON", noticeCredential); err != ErrProfile {
		t.Fatal("ordinary insecure host accepted")
	}
}
