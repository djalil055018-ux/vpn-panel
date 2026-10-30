package agent

import "testing"

func TestParseTrafficCounters(t *testing.T) {
	raw := []byte(`{"stat":[{"name":"user>>>client-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@vpn-platform.invalid>>>traffic>>>uplink","value":"123"},{"name":"user>>>client-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@vpn-platform.invalid>>>traffic>>>downlink","value":456},{"name":"user>>>foreign@example.com>>>traffic>>>uplink","value":9},{"name":"inbound>>>api>>>traffic>>>uplink","value":10}]}`)
	got := parseTrafficCounters(raw)
	if len(got) != 1 || got[0].ClientID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || got[0].Uplink != 123 || got[0].Downlink != 456 {
		t.Fatalf("unexpected traffic: %+v", got)
	}
}

func TestParseOnlineClientCountsDoesNotRetainAddresses(t *testing.T) {
	raw := []byte(`{"users":[{"email":"client-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@vpn-platform.invalid","ips":[{"ip":"192.0.2.1"},{"ip":"198.51.100.2"}]},{"email":"foreign@example.com","ips":[{"ip":"203.0.113.1"}]}]}`)
	got := parseOnlineClientCounts(raw)
	if len(got) != 1 || got["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"] != 2 {
		t.Fatalf("unexpected online counts: %+v", got)
	}
}
