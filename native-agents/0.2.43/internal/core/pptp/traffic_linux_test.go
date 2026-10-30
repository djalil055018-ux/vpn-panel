//go:build linux

package pptp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testClient = "a1234567-1234-4567-8123-123456789abc"
const testInvocation = "1234567890abcdef1234567890abcdef"
const nextInvocation = "2234567890abcdef1234567890abcdef"
const testSession = "1234567890abcdef"

func testLedger() ledger {
	return ledger{Format: 1, Epoch: strings.Repeat("a", 32), Totals: map[string]counters{}, Active: map[string]Session{}}
}
func expectCounts(t *testing.T, l *ledger, up, down int64) {
	t.Helper()
	got, e := l.counts()
	if e != nil || len(got) != 1 || got[0].ClientID != testClient || got[0].Uplink != up || got[0].Downlink != down || !got[0].ActiveIPsUnavailable {
		t.Fatalf("wrong cumulative traffic: %#v %v", got, e)
	}
}

func TestPPTPTrafficSessionBoundaries(t *testing.T) {
	l := testLedger()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	check(l.apply(testInvocation, "begin", nil))
	s := Session{ID: testSession, ClientID: testClient}
	check(l.apply(testInvocation, "start", []Session{s}))
	s.Uplink = 100
	s.Downlink = 200
	check(l.apply(testInvocation, "sample", []Session{s}))
	expectCounts(t, &l, 100, 200)
	check(l.apply(testInvocation, "start", []Session{s}))
	check(l.apply(testInvocation, "begin", nil))
	expectCounts(t, &l, 100, 200)
	s.Uplink = 90
	s.Downlink = 150
	check(l.apply(testInvocation, "sample", []Session{s}))
	expectCounts(t, &l, 100, 200)
	s.Uplink = 120
	s.Downlink = 220
	check(l.apply(testInvocation, "finish", []Session{s}))
	check(l.apply(testInvocation, "finish", []Session{s}))
	check(l.apply(testInvocation, "sample", []Session{s}))
	expectCounts(t, &l, 120, 220)
	s.ID = "2234567890abcdef"
	check(l.apply(testInvocation, "start", []Session{s}))
	s.Uplink = 20
	s.Downlink = 30
	check(l.apply(testInvocation, "sample", []Session{s}))
	expectCounts(t, &l, 140, 250)
	// A crashed daemon contributes its last durable counters once. An old hook
	// cannot modify a later invocation, even if the client's next session exists.
	check(l.apply(nextInvocation, "begin", nil))
	expectCounts(t, &l, 140, 250)
	if l.apply(testInvocation, "finish", []Session{s}) == nil {
		t.Fatal("stale invocation accepted")
	}
	check(l.apply(nextInvocation, "begin", nil))
	expectCounts(t, &l, 140, 250)
	s.ID = "3234567890abcdef"
	check(l.apply(nextInvocation, "start", []Session{s}))
	s.Uplink = 7
	s.Downlink = 9
	check(l.apply(nextInvocation, "finish", []Session{s}))
	expectCounts(t, &l, 147, 259)
}

func TestPPTPInvalidTrafficFailsClosed(t *testing.T) {
	l := testLedger()
	l.apply(testInvocation, "begin", nil)
	s := Session{ID: testSession, ClientID: testClient}
	l.apply(testInvocation, "start", []Session{s})
	foreign := s
	foreign.ClientID = "b1234567-1234-4567-8123-123456789abc"
	if l.apply(testInvocation, "start", []Session{foreign}) == nil {
		t.Fatal("session identity collision accepted")
	}
	if l.apply(testInvocation, "sample", []Session{foreign}) == nil {
		t.Fatal("counter identity collision accepted")
	}
	duplicate := s
	duplicate.ID = "2234567890abcdef"
	if l.apply(testInvocation, "start", []Session{duplicate}) == nil {
		t.Fatal("concurrent client sessions accepted")
	}
	s.Uplink = -1
	if l.apply(testInvocation, "finish", []Session{s}) == nil {
		t.Fatal("negative counter accepted")
	}
	l.Totals[testClient] = counters{maxCounter, 0}
	s.Uplink = 1
	l.Active[s.ID] = s
	if _, e := l.counts(); e == nil {
		t.Fatal("counter overflow accepted")
	}
}

func TestPPTPRawSessionParsing(t *testing.T) {
	raw := "sid | username | rx-bytes-raw | tx-bytes-raw | state | ifname\n----+----+----+----+----+----\n" + testSession + " | " + testClient + " | 1230634 | 1221826 | active | vppptp0\n"
	sessions, e := parseSessions([]byte(raw))
	if e != nil || len(sessions) != 1 || sessions[0].Uplink != 1230634 || sessions[0].Downlink != 1221826 {
		t.Fatalf("native counter fixture rejected: %v", e)
	}
	for _, bad := range []string{"", strings.Replace(raw, "rx-bytes-raw", "rx-bytes", 1), strings.Replace(raw, "1230634", "-1", 1), strings.Replace(raw, "vppptp0", "eth0", 1), raw + strings.Split(raw, "\n")[2] + "\n", strings.Replace(raw, testSession, "invalid", 1)} {
		if _, e = parseSessions([]byte(bad)); e == nil {
			t.Fatal("malformed traffic accepted")
		}
	}
	if values, e := parseSessions([]byte(strings.Join(strings.Split(raw, "\n")[:2], "\n"))); e != nil || len(values) != 0 {
		t.Fatal("empty active table rejected")
	}
}

func TestPPTPDurableLedgerConcurrentHooks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned runtime filesystem required")
	}
	root, e := os.MkdirTemp("/run", "vpn-pptp-ledger-test-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	ctx := context.Background()
	epoch, _, e := trafficLedger(ctx, root, "", "initialize", nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = trafficLedger(ctx, root, testInvocation, "begin", nil); e != nil {
		t.Fatal(e)
	}
	s := Session{ID: testSession, ClientID: testClient}
	if _, _, e = trafficLedger(ctx, root, testInvocation, "start", []Session{s}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sample := s
			sample.Uplink = int64(i)
			sample.Downlink = int64(i * 2)
			_, _, e := trafficLedger(ctx, root, testInvocation, "sample", []Session{sample})
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	s.Uplink = 30
	s.Downlink = 60
	if _, _, e = trafficLedger(ctx, root, testInvocation, "finish", []Session{s}); e != nil {
		t.Fatal(e)
	}
	gotEpoch, clients, e := trafficLedger(ctx, root, "", "read", nil)
	if e != nil || gotEpoch != epoch || len(clients) != 1 || clients[0].Uplink != 30 || clients[0].Downlink != 60 {
		t.Fatal("durable cumulative counters differ")
	}
	if e = os.WriteFile(filepath.Join(root, "traffic.json"), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = trafficLedger(ctx, root, "", "initialize", nil); e == nil {
		t.Fatal("corrupt ledger silently reset")
	}
	if e = os.Remove(filepath.Join(root, "traffic.json")); e != nil {
		t.Fatal(e)
	}
	if _, _, e = trafficLedger(ctx, root, "", "read", nil); e == nil {
		t.Fatal("missing ledger silently reset")
	}
}
