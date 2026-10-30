//go:build linux

package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"vpn-platform/internal/model"
)

func TestTrafficWorkerKeepsUnacknowledgedSamplesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	outbox, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	value := outboxFixture(1)
	worker := &TrafficWorker{outbox: outbox, collect: func(context.Context, bool) (*model.TrafficDelivery, error) { return &value, nil }}
	if err = worker.Capture(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	worker.send = func(context.Context, model.TrafficDelivery) error { return errors.New("response lost after commit") }
	if err = worker.Drain(context.Background(), 16); err == nil {
		t.Fatal("transport failure ignored")
	}
	status, err := outbox.Status()
	if err != nil || status.Pending != 1 {
		t.Fatal("unacknowledged sample deleted")
	}
	// A new process sees the old epoch before the new runtime's counters.
	reopened, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	fresh := outboxFixture(2)
	fresh.Snapshot.Epoch = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err = reopened.Put(fresh); err != nil {
		t.Fatal(err)
	}
	sent := []int64{}
	restarted := &TrafficWorker{outbox: reopened, send: func(_ context.Context, v model.TrafficDelivery) error {
		sent = append(sent, v.Snapshot.Sequence)
		return nil
	}}
	if err = restarted.Drain(context.Background(), 16); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sent, []int64{1, 2}) {
		t.Fatal("pending epoch bypassed after restart")
	}
	status, err = reopened.Status()
	if err != nil || status.Pending != 0 {
		t.Fatal("acknowledged queue not drained")
	}
}

func TestTrafficWorkerCacheAndFinalCapture(t *testing.T) {
	outbox, err := NewTrafficOutbox(t.TempDir(), outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	value := outboxFixture(1)
	forced := false
	worker := &TrafficWorker{outbox: outbox, collect: func(_ context.Context, force bool) (*model.TrafficDelivery, error) {
		if force {
			forced = true
			value = outboxFixture(2)
		}
		return &value, nil
	}, send: func(context.Context, model.TrafficDelivery) error { return nil }}
	if err = worker.Capture(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err = worker.Drain(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err = worker.Capture(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	status, err := outbox.Status()
	if err != nil || status.Pending != 0 {
		t.Fatal("cached acknowledged sample re-enqueued")
	}
	worker.BeforeStop(context.Background())
	status, err = outbox.Status()
	if err != nil || status.Pending != 1 || !forced {
		t.Fatal("final capture did not bypass cache")
	}
}
