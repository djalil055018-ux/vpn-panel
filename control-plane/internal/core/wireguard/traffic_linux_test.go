//go:build linux

package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTrafficSurvivesInterfaceReplacementAndRetry(t *testing.T) {
	root := testRoot(t)
	l, err := OpenTrafficLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	id := "11111111-1111-4111-8111-111111111111"
	peers := func(rx, tx int64) map[string]PeerCounter { return map[string]PeerCounter{key: {id, Counter{rx, tx}}} }
	epoch, totals, err := l.Sample(strings.Repeat("a", 32), peers(100, 200))
	if err != nil || totals[0].Uplink != 100 {
		t.Fatal("initial sample", err)
	}
	// Simulate restarting the agent with the same running kernel interface.
	l, err = OpenTrafficLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	again, totals, err := l.Sample(strings.Repeat("a", 32), peers(100, 200))
	if err != nil || again != epoch || totals[0].Uplink != 100 {
		t.Fatal("retry double counted", err)
	}
	if _, _, err = l.Sample(strings.Repeat("a", 32), peers(99, 200)); err == nil {
		t.Fatal("external reset silently accepted")
	}
	_, totals, err = l.Sample(strings.Repeat("a", 32), peers(120, 250))
	if err != nil || totals[0].Downlink != 250 {
		t.Fatal("delta failed", err)
	}
	again, totals, err = l.Sample(strings.Repeat("b", 32), peers(5, 7))
	if err != nil || again != epoch || totals[0].Uplink != 125 || totals[0].Downlink != 257 {
		t.Fatal("interface reset lost traffic", err)
	}
	_, totals, err = l.Sample(strings.Repeat("c", 32), map[string]PeerCounter{})
	if err != nil || totals[0].Uplink != 125 {
		t.Fatal("revoke lost unreported totals", err)
	}
}
func TestTransferParserRejectsUnknownMissingAndOverflow(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	owners := map[string]string{key: "11111111-1111-4111-8111-111111111111"}
	for _, raw := range []string{"", key + " 1 2\n" + key + " 1 2", key + " -1 2", key + " 9223372036854775808 2", key + " 1 2 extra"} {
		if _, err := ParseTransfers(raw, owners); err == nil {
			t.Fatal("malformed transfer accepted")
		}
	}
	parsed, err := ParseTransfers(key+"\t13\t29\n", owners)
	if err != nil || parsed[key].Counter.Uplink != 13 || parsed[key].Counter.Downlink != 29 {
		t.Fatal("transfer direction mismatch")
	}
}
