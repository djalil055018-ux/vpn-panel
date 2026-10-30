//go:build linux

package openvpn

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTrafficSessionRoamingRapidReconnectAndCompaction(t *testing.T) {
	l := ledger{Epoch: strings.Repeat("a", 32)}
	if err := l.normalize(); err != nil {
		t.Fatal(err)
	}
	s := Session{ClientID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Invocation: strings.Repeat("b", 32), Started: 100, Remote: "192.0.2.1:1000"}
	apply := func(event string, s Session, now int64) {
		t.Helper()
		if err := l.apply(s.Invocation, event, []Session{s}, now); err != nil {
			t.Fatal(err)
		}
	}
	apply("client-connect", s, 100)
	s.Uplink = 100
	s.Downlink = 200
	s.ObservedAt = 102
	apply("", s, 102)
	s.Remote = "198.51.100.1:2000"
	s.Uplink = 130
	s.Downlink = 250
	s.ObservedAt = 103
	apply("", s, 103)
	apply("client-disconnect", s, 103)
	apply("client-disconnect", s, 103)
	if l.Totals[s.ClientID] != (counters{130, 250}) || len(l.Active) != 0 {
		t.Fatal("roaming or final event counted twice")
	}
	// The same timestamp, endpoint and CN still denotes a NEW hook-delimited
	// session. A status publication preceding its connect cannot count old bytes.
	apply("client-connect", s, 103)
	apply("", s, 103)
	if l.Active[s.ClientID].Uplink != 0 {
		t.Fatal("stale status counted into next session")
	}
	s.Uplink = 20
	s.Downlink = 30
	apply("client-disconnect", s, 103)
	if l.Totals[s.ClientID] != (counters{150, 280}) {
		t.Fatal("rapid reconnect lost bytes")
	}
	for i := 0; i < 100001; i++ {
		apply("client-connect", s, 104)
		apply("client-disconnect", s, 104)
	}
	if len(l.Totals) != 1 || len(l.Active) != 0 || len(l.Sessions) != 0 {
		t.Fatal("ledger grows with closed connections")
	}
	if l.Totals[s.ClientID] != (counters{2000170, 3000310}) {
		t.Fatal("compaction changed cumulative counters")
	}
}
func TestTrafficLegacyLedgerAndDaemonRestart(t *testing.T) {
	broken := ledger{Epoch: strings.Repeat("a", 32), Totals: map[string]counters{}}
	if broken.normalize() == nil {
		t.Fatal("missing format discarded cumulative counters")
	}
	s := Session{ClientID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Invocation: strings.Repeat("b", 32), Started: 100, Uplink: 100, Downlink: 200}
	l := ledger{Epoch: strings.Repeat("a", 32), Sessions: map[string]Session{"old": s}}
	if err := l.normalize(); err != nil {
		t.Fatal(err)
	}
	if l.Totals[s.ClientID] != (counters{100, 200}) || l.Format != 2 || l.Sessions != nil {
		t.Fatal("legacy migration lost counters")
	}
	l.apply(s.Invocation, "client-connect", []Session{s}, 100)
	s.ObservedAt = 103
	l.apply(s.Invocation, "", []Session{s}, 103)
	l.apply(strings.Repeat("c", 32), "", nil, 104)
	if len(l.Active) != 0 || l.Totals[s.ClientID] != (counters{200, 400}) {
		t.Fatal("daemon restart lost sampled counters")
	}
}
func TestTrafficStatusHeaderMappingAndTruncation(t *testing.T) {
	raw := fmt.Sprintf("TIME\tnow\t%d\nHEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since (time_t)\nCLIENT_LIST\tclient-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\t192.0.2.1:12345\t10.77.0.2\t123\t456\t1700000000\nEND\n", time.Now().Unix())
	got, err := parseStatus([]byte(raw), strings.Repeat("a", 32))
	if err != nil || len(got) != 1 || got[0].Uplink != 123 || got[0].Downlink != 456 {
		t.Fatalf("parse: %v", err)
	}
	if _, err = parseStatus([]byte(strings.TrimSuffix(raw, "END\n")), strings.Repeat("a", 32)); err == nil {
		t.Fatal("partially rewritten status accepted")
	}
	if _, err = parseStatus([]byte("TIME\told\t1\nEND\n"), strings.Repeat("a", 32)); err == nil {
		t.Fatal("stale status accepted")
	}
}
