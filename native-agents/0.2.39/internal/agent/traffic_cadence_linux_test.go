//go:build linux

package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

// Manual ticks reproduce the cache/ticker boundary without waiting a minute.
// The collector has an unexpired older sample; every scheduled poll must still
// enqueue the current counters, using a distinct ordered sequence.
func TestScheduledCaptureRefreshesUnexpiredCacheOnEveryTick(t *testing.T) {
	outbox, err := NewTrafficOutbox(t.TempDir(), outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	cached := outboxFixture(1)
	var currentBytes atomic.Int64
	currentBytes.Store(1000)
	worker := &TrafficWorker{outbox: outbox, collect: func(ctx context.Context, force bool) (*model.TrafficDelivery, error) {
		if force {
			cached = outboxFixture(cached.Snapshot.Sequence + 1)
			cached.Snapshot.Clients[0].Downlink = currentBytes.Load()
		}
		value := cached
		return &value, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { defer close(done); worker.runScheduledCapture(ctx, ticks) }()
	defer func() { cancel(); <-done }()
	awaitPending := func(count int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			status, err := outbox.Status()
			if err != nil {
				t.Fatal(err)
			}
			if status.Pending == count {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("scheduled tick reused the cached sample")
	}
	awaitPending(1)
	first, err := outbox.Peek()
	if err != nil || first == nil || first.Snapshot.Sequence != 2 || first.Snapshot.Clients[0].Downlink != 1000 {
		t.Fatal("initial scheduled capture did not refresh the cached counters")
	}
	currentBytes.Store(2000)
	ticks <- time.Now()
	awaitPending(2)
	cancel()
	<-done
	if err = outbox.Acknowledge(2); err != nil {
		t.Fatal(err)
	}
	second, err := outbox.Peek()
	if err != nil || second == nil || second.Snapshot.Sequence != 3 || second.Snapshot.Clients[0].Downlink != 2000 {
		t.Fatal("next scheduled tick omitted new traffic inside the cache lifetime")
	}
}
