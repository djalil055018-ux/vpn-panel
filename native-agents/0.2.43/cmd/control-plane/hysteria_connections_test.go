package main

import (
	"net/url"
	"testing"
	"vpn-platform/internal/model"
)

func TestHysteriaSubscriptionURI(t *testing.T) {
	c := model.VPNClientConnection{Protocol: "hysteria2", Transport: "udp", Security: "tls", UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Address: "2001:db8::1", Port: 443, ServerName: "hys.example.test", ClientName: "Fixture", ServiceName: "Sweden"}
	value, err := buildVPNConnectionURI(c)
	if err != nil {
		t.Fatal("valid Hysteria connection rejected")
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "hysteria2" || u.Host != "[2001:db8::1]:443" || u.User.Username() != c.UUID || u.Fragment != "PAUK - Sweden" {
		t.Fatal("Hysteria URI identity invalid")
	}
	q := u.Query()
	if len(q) != 2 || q.Get("sni") != c.ServerName || q.Get("insecure") != "0" {
		t.Fatal("unexpected subscription settings")
	}
	c.Transport = "tcp"
	if _, err = buildVPNConnectionURI(c); err == nil {
		t.Fatal("unsupported Hysteria transport advertised")
	}
}
