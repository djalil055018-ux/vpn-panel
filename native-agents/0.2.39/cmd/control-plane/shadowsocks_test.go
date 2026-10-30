package main

import (
	"encoding/base64"
	"net/url"
	"testing"
	"vpn-platform/internal/model"
)

func TestShadowsocksURI(t *testing.T) {
	a := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	b := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	c := model.VPNClientConnection{Protocol: "shadowsocks", Transport: "tcp,udp", Security: "shadowsocks", Address: "2001:db8::1", Port: 8388, Password: a + ":" + b, ClientName: "Клиент #1", ServiceName: "SS / 2022"}
	uri, err := buildVPNConnectionURI(c)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	password, ok := u.User.Password()
	if u.Scheme != "ss" || u.User.Username() != model.ShadowsocksMethod || !ok || password != c.Password || u.Hostname() != c.Address || u.Fragment != "PAUK - SS / 2022" {
		t.Fatal("SIP002 URI did not round-trip")
	}
	for _, bad := range []string{"", a, a + ":" + a, a + ":" + b + ":" + a, "invalid:" + b} {
		c.Password = bad
		if _, err := buildVPNConnectionURI(c); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
}
