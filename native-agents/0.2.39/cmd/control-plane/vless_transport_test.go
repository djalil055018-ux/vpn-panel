package main

import (
	"net/url"
	"testing"

	"vpn-platform/internal/model"
)

func TestVLESSWebTransportShareLinks(t *testing.T) {
	for _, transport := range []string{"ws", "grpc"} {
		t.Run(transport, func(t *testing.T) {
			c := model.VPNClientConnection{Protocol: "vless", Transport: transport, Security: "tls", UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ServiceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Address: "2001:db8::1", Port: 443, ServerName: "vpn.example.test", ClientName: "Клиент", ServiceName: "Тест"}
			uri, err := buildVPNConnectionURI(c)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if u.Scheme != "vless" || u.Hostname() != c.Address || u.User.Username() != c.UUID || q.Get("type") != transport || q.Get("security") != "tls" || q.Get("sni") != c.ServerName {
				t.Fatal("connection identity lost")
			}
			if transport == "ws" {
				path, _ := model.XHTTPPath(c.ServiceID)
				if q.Get("path") != path || q.Get("host") != c.ServerName {
					t.Fatal("WebSocket path or host lost")
				}
			} else {
				name, _ := model.GRPCServiceName(c.ServiceID)
				if q.Get("serviceName") != name || q.Get("mode") != "gun" {
					t.Fatal("gRPC service name or mode lost")
				}
			}
			c.Protocol = "trojan"
			if _, err = buildVPNConnectionURI(c); err == nil {
				t.Fatal("unsupported Trojan transport exported")
			}
			c.Protocol = "vless"
			c.ServiceID = "../../invalid"
			if _, err = buildVPNConnectionURI(c); err == nil {
				t.Fatal("unsafe service ID exported")
			}
		})
	}
}
