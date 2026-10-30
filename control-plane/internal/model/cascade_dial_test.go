package model

import "testing"

func TestCascadeDialBoundsAndIdentity(t *testing.T) {
	cases := []struct {
		ip    string
		count int
		valid bool
	}{
		{"", 0, true}, {"192.0.2.10", 2, true}, {"192.0.2.10", 16, true}, {"10.20.30.40", 8, true},
		{"", 2, false}, {"192.0.2.10", 0, false}, {"192.0.2.10", 1, false}, {"192.0.2.10", 17, false},
		{"proxy.example", 8, false}, {"127.0.0.1", 8, false}, {"0.0.0.0", 8, false}, {"169.254.1.1", 8, false},
		{"224.0.0.1", 8, false}, {"::1", 8, false}, {"2001:db8::1", 8, false}, {"::ffff:192.0.2.10", 8, false},
	}
	for _, c := range cases {
		if ValidCascadeDial(c.ip, c.count) != c.valid {
			t.Fatal("dial policy bounds changed")
		}
	}
	for version, want := range map[string]bool{"0.2.43": false, "0.2.44": true, "0.2.45": true, "1.0.0": true, "0.2.44-dev": false} {
		if CascadeDialAgentCompatible(version) != want {
			t.Fatal("dial policy agent floor changed")
		}
	}
}
