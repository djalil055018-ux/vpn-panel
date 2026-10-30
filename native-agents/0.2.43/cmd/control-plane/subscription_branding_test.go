package main

import (
	"encoding/base64"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"vpn-platform/internal/model"
)

func TestSubscriptionBrandingClientHeaders(t *testing.T) {
	for _, name := range []string{"PAUK", "Паук VPN"} {
		headers := http.Header{}
		setSubscriptionBranding(headers, name)
		title := headers.Get("Profile-Title")
		if name == "PAUK" && title != name {
			t.Fatal("PAUK title missing")
		}
		if name != "PAUK" && title != "base64:"+base64.StdEncoding.EncodeToString([]byte(name)) {
			t.Fatal("Unicode title not encoded")
		}
		_, params, err := mime.ParseMediaType(headers.Get("Content-Disposition"))
		if err != nil || params["filename"] != name {
			t.Fatal("client fallback lost")
		}
	}
}

func TestVPNBrandChangesOnlyPublicConnectionName(t *testing.T) {
	for _, transport := range []string{"tcp", "ws", "grpc", "xhttp"} {
		c := model.VPNClientConnection{Protocol: "vless", Transport: transport, Security: "tls", UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ServiceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Address: "vpn.example.test", Port: 443, ServerName: "tls.example.test", ClientName: "TEST1", ServiceName: "Sweden"}
		before, err := buildVPNConnectionURI(c)
		if err != nil {
			t.Fatal(err)
		}
		c.BrandName = "Другой бренд"
		after, err := buildVPNConnectionURI(c)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := url.Parse(before)
		b, _ := url.Parse(after)
		if a.Fragment != "PAUK - Sweden" || b.Fragment != "Другой бренд - Sweden" || c.ClientName != "TEST1" {
			t.Fatal("public display name or account name incorrect")
		}
		a.Fragment = ""
		b.Fragment = ""
		if a.String() != b.String() {
			t.Fatal("branding changed connection parameters")
		}
	}
}

func TestImportedSubscriptionUsesNativeBrandWithoutChangingPayload(t *testing.T) {
	snapshot := publicSubscriptionFixture()
	snapshot.Policy.Headers["profile-title"] = "Old VPN"
	req := httptest.NewRequest("GET", "https://example.test/sub/synthetic", nil)
	req.Header.Set("User-Agent", "curl/8")
	before := httptest.NewRecorder()
	writeImportedSubscription(before, req, snapshot)
	snapshot.BrandName = "PAUK"
	after := httptest.NewRecorder()
	writeImportedSubscription(after, req, snapshot)
	if before.Code != 200 || after.Code != 200 || after.Header().Get("Profile-Title") != "PAUK" || after.Header().Get("Content-Disposition") != "attachment; filename=PAUK" {
		t.Fatal("imported profile title incorrect")
	}
	if before.Body.String() != after.Body.String() || before.Header().Get("Subscription-Userinfo") != after.Header().Get("Subscription-Userinfo") {
		t.Fatal("branding changed credentials, endpoints or quota")
	}
}
