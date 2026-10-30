package compiler

import (
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func pptpFixture() model.ServiceSpec {
	id := "a1234567-1234-4567-8123-123456789abc"
	return model.ServiceSpec{ID: id, Protocol: "pptp", Listen: "0.0.0.0", Port: 1723, Transport: "tcp,gre", Security: "mppe", Clients: []model.ClientSpec{{ID: id, StatsKey: id, PPTP: &model.PPTPPeer{Password: strings.Repeat("a", 64), Address: "10.78.0.2"}}}}
}

func TestPPTPStrictBoundary(t *testing.T) {
	checks := map[string]func(*model.ServiceSpec){
		"newline listen":           func(s *model.ServiceSpec) { s.Listen = "0.0.0.0\n[modules]\nauth_pap" },
		"ipv6":                     func(s *model.ServiceSpec) { s.Listen = "::" },
		"mapped ipv4":              func(s *model.ServiceSpec) { s.Listen = "::ffff:127.0.0.1" },
		"nonstandard port":         func(s *model.ServiceSpec) { s.Port = 443 },
		"plaintext":                func(s *model.ServiceSpec) { s.Security = "none" },
		"different stats identity": func(s *model.ServiceSpec) { s.Clients[0].StatsKey = "b1234567-1234-4567-8123-123456789abc" },
		"missing credential":       func(s *model.ServiceSpec) { s.Clients[0].PPTP = nil },
		"secret directive":         func(s *model.ServiceSpec) { s.Clients[0].PPTP.Password = "bad\n* * password *" },
		"short secret":             func(s *model.ServiceSpec) { s.Clients[0].PPTP.Password = "password" },
		"address escape":           func(s *model.ServiceSpec) { s.Clients[0].PPTP.Address = "192.168.1.1" },
		"server address":           func(s *model.ServiceSpec) { s.Clients[0].PPTP.Address = "10.78.0.1" },
		"broadcast":                func(s *model.ServiceSpec) { s.Clients[0].PPTP.Address = "10.78.0.255" },
		"duplicate identity":       func(s *model.ServiceSpec) { s.Clients = append(s.Clients, s.Clients[0]) },
		"duplicate address": func(s *model.ServiceSpec) {
			c := s.Clients[0]
			c.ID = "b1234567-1234-4567-8123-123456789abc"
			c.StatsKey = c.ID
			s.Clients = append(s.Clients, c)
		},
		"mixed protocol config": func(s *model.ServiceSpec) { s.OpenVPN = &model.OpenVPNSpec{} },
	}
	for name, alter := range checks {
		t.Run(name, func(t *testing.T) {
			s := pptpFixture()
			alter(&s)
			if _, _, err := CompilePPTP(s, strings.Repeat("b", 64)); err == nil {
				t.Fatal("unsafe service accepted")
			}
		})
	}
}

func TestPPTPMPPEAndCredentialCompilation(t *testing.T) {
	s := pptpFixture()
	c, secrets, err := CompilePPTP(s, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"auth_mschap_v2\n", "mppe=require\n", "ipv6=deny\n", "single-session=deny\n", "sid-source=urandom\n", "bind=0.0.0.0\n", "port=1723\n", "ip-pre-up=./ip-pre-up\n", "ip-down=./ip-down\n"} {
		if !strings.Contains(string(c), required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"auth_pap", "auth_chap_md5", "auth_mschap_v1", "radius", "ipv6=allow"} {
		if strings.Contains(string(c), forbidden) {
			t.Fatalf("unexpected %s", forbidden)
		}
	}
	if string(secrets) != s.Clients[0].ID+" * "+strings.Repeat("a", 64)+" 10.78.0.2\n" {
		t.Fatal("incorrect credential mapping")
	}
	if _, _, err = CompilePPTP(s, "invalid"); err == nil {
		t.Fatal("missing CLI protection accepted")
	}
	s.Clients = nil
	if _, secrets, err = CompilePPTP(s, strings.Repeat("b", 64)); err != nil || len(secrets) != 0 {
		t.Fatal("empty allowlist must contain no wildcard credentials")
	}
}
