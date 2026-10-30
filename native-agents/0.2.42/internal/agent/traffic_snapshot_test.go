package agent

import (
	"context"
	"testing"
	"time"
)

func TestTrafficSnapshotStableRuntimeAndCache(t *testing.T) {
	oldEpoch, oldNext, oldCounters, oldOnline := runTrafficEpochCommand, nextTrafficSequence, runTrafficCountersCommand, runOnlineClientsCommand
	oldAt, oldCache := trafficAt, trafficCache
	t.Cleanup(func() {
		runTrafficEpochCommand = oldEpoch
		nextTrafficSequence = oldNext
		runTrafficCountersCommand = oldCounters
		runOnlineClientsCommand = oldOnline
		trafficAt = oldAt
		trafficCache = oldCache
	})
	trafficAt = time.Time{}
	trafficCache = nil
	epoch := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var sequence int64
	nextTrafficSequence = func() (int64, error) { sequence++; return sequence, nil }
	runTrafficEpochCommand = func(context.Context) (string, error) { return epoch, nil }
	runTrafficCountersCommand = func(context.Context) ([]byte, error) {
		return []byte(`{"stat":[{"name":"user>>>client-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@vpn-platform.invalid>>>traffic>>>uplink","value":123}]}`), nil
	}
	runOnlineClientsCommand = func(context.Context) ([]byte, error) { return []byte(`{"users":[]}`), nil }
	a := CollectClientTraffic()
	if a == nil || a.Sequence != 1 || a.Epoch != epoch || len(a.Clients) != 1 {
		t.Fatal("snapshot metadata missing")
	}
	a.Clients[0].Uplink = 999
	b := CollectClientTraffic()
	if b == nil || b.Sequence != 1 || sequence != 1 || b.Clients[0].Uplink != 123 {
		t.Fatal("cache changed identity or shared mutable samples")
	}
	trafficAt = time.Time{}
	calls := 0
	runTrafficEpochCommand = func(context.Context) (string, error) {
		calls++
		if calls == 1 {
			return epoch, nil
		}
		return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
	}
	if CollectClientTraffic() != nil {
		t.Fatal("snapshot spanned an Xray restart")
	}
	if sequence != 2 {
		t.Fatal("failed sample must consume its reserved sequence")
	}
}
