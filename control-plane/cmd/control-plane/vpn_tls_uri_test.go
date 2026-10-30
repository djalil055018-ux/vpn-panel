package main

import (
	"net/url"
	"testing"
	"vpn-platform/internal/model"
)

func TestTLSSubscriptionURI(t *testing.T) {
	c := model.VPNClientConnection{Address: "test.example", Port: 8443, Protocol: "vless", Transport: "tcp", Security: "tls", UUID: "11111111-1111-4111-8111-111111111111", ServerName: "test.example", Password: "must-not-appear", ShortID: "must-not-appear"}
	raw, err := buildVPNConnectionURI(c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("security") != "tls" || q.Get("sni") != "test.example" || q.Has("pbk") || q.Has("sid") || q.Has("allowInsecure") {
		t.Fatal("invalid TLS subscription parameters")
	}
	c.ServerName = ""
	if _, err = buildVPNConnectionURI(c); err == nil {
		t.Fatal("missing SNI accepted")
	}
}

func TestTrojanSubscriptionURI(t *testing.T) {
	c := model.VPNClientConnection{Address: "test.example", Port: 8443, Protocol: "trojan", Transport: "tcp", Security: "tls", UUID: "11111111-1111-4111-8111-111111111111", ServerName: "test.example"}
	raw, err := buildVPNConnectionURI(c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "trojan" || u.User.Username() != c.UUID || u.Query().Get("security") != "tls" || u.Query().Has("encryption") || u.Query().Has("allowInsecure") {
		t.Fatal("invalid Trojan subscription URI")
	}
}
