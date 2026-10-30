package main

import (
	"net/url"
	"testing"
	"vpn-platform/internal/model"
)

func TestXHTTPSubscriptionURI(t *testing.T) {
	c := model.VPNClientConnection{ServiceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", UUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Protocol: "vless", Transport: "xhttp", Security: "tls", Address: "test.example", Port: 8443, ServerName: "test.example"}
	raw, err := buildVPNConnectionURI(c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("invalid URI")
	}
	path, _ := model.XHTTPPath(c.ServiceID)
	if u.Scheme != "vless" || u.Query().Get("path") != path || u.Query().Get("mode") != "auto" || u.Query().Get("type") != "xhttp" || u.Query().Get("security") != "tls" || u.Query().Get("sni") != c.ServerName {
		t.Fatal("XHTTP subscription fields mismatch")
	}
	c.ServiceID = "../bad"
	if _, err = buildVPNConnectionURI(c); err == nil {
		t.Fatal("invalid path accepted")
	}
	c.Protocol = "trojan"
	if _, err = buildVPNConnectionURI(c); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
}
