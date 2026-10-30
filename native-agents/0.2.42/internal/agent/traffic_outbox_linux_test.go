//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

const outboxTestNode = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func TestTrafficOutboxPreservesUnknownAddressTelemetryAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	outbox, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	value := outboxFixture(1)
	value.Snapshot.Clients[0].ActiveIPsUnavailable = true
	if err = outbox.Put(value); err == nil {
		t.Fatal("contradictory address count accepted")
	}
	value.Snapshot.Clients[0].ActiveIPs = 0
	if err = outbox.Put(value); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Peek()
	if err != nil || pending == nil || !pending.Snapshot.Clients[0].ActiveIPsUnavailable || pending.Snapshot.Clients[0].Uplink != 123 {
		t.Fatal("durable queue lost unknown address telemetry or bytes")
	}
}

func outboxFixture(sequence int64) model.TrafficDelivery {
	return model.TrafficDelivery{RecordedAt: time.Date(2026, 9, 10, 6, 0, 0, 0, time.UTC), Snapshot: model.ClientTrafficSnapshot{Sequence: sequence, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Clients: []model.ClientTraffic{{ClientID: outboxTestNode, Uplink: 123, Downlink: 456, ActiveIPs: 2}}}}
}

func TestTrafficOutboxPersistsOrdersAndAcknowledges(t *testing.T) {
	dir := t.TempDir()
	o, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []int64{3, 1, 2} {
		if err = o.Put(outboxFixture(seq)); err != nil {
			t.Fatal(err)
		}
	}
	if err = o.Put(outboxFixture(1)); err != nil {
		t.Fatal("idempotent enqueue failed")
	}
	other, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	status, err := other.Status()
	if err != nil || status.Pending != 3 || status.Bytes <= 0 || status.Oldest.IsZero() {
		t.Fatal("durable status missing")
	}
	if err = other.Acknowledge(2); err == nil {
		t.Fatal("out-of-order acknowledgement deleted sample")
	}
	for seq := int64(1); seq <= 3; seq++ {
		value, err := other.Peek()
		if err != nil || value == nil || value.Snapshot.Sequence != seq {
			t.Fatal("pending sample lost or reordered")
		}
		if err = other.Acknowledge(seq); err != nil {
			t.Fatal(err)
		}
	}
	if value, err := other.Peek(); err != nil || value != nil {
		t.Fatal("acknowledged queue not empty")
	}
	if _, err = NewTrafficOutbox(dir, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"); !errors.Is(err, ErrTrafficOutboxCorrupt) {
		t.Fatal("outbox rebound to another node")
	}
}

func TestTrafficOutboxCapacityNeverEvictsPending(t *testing.T) {
	o, err := NewTrafficOutbox(t.TempDir(), outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	o.maxRecords = 2
	for _, seq := range []int64{1, 2} {
		if err = o.Put(outboxFixture(seq)); err != nil {
			t.Fatal(err)
		}
	}
	if err = o.Put(outboxFixture(3)); !errors.Is(err, ErrTrafficOutboxFull) {
		t.Fatal("queue limit ignored")
	}
	first, err := o.Peek()
	if err != nil || first.Snapshot.Sequence != 1 {
		t.Fatal("oldest sample evicted")
	}
	if err = o.Acknowledge(1); err != nil {
		t.Fatal(err)
	}
	if err = o.Put(outboxFixture(3)); err != nil {
		t.Fatal("queue did not resume after acknowledgement")
	}
}

func TestTrafficOutboxCorruptionIsPreservedAndRejected(t *testing.T) {
	dir := t.TempDir()
	o, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Put(outboxFixture(1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "0000000000000001.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Still valid JSON, but the cumulative counter was corrupted.
	raw = []byte(strings.Replace(string(raw), `"uplink_bytes":123`, `"uplink_bytes":124`, 1))
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = o.Peek(); !errors.Is(err, ErrTrafficOutboxCorrupt) {
		t.Fatal("checksum corruption accepted")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("corrupt evidence deleted")
	}
	changed := outboxFixture(1)
	changed.Snapshot.Clients[0].Uplink = 999
	if err = o.Put(changed); !errors.Is(err, ErrTrafficOutboxCorrupt) {
		t.Fatal("existing sequence overwritten")
	}
	if err = os.Remove(filepath.Join(dir, "owner")); err != nil {
		t.Fatal(err)
	}
	if _, err = NewTrafficOutbox(dir, outboxTestNode); !errors.Is(err, ErrTrafficOutboxCorrupt) {
		t.Fatal("ownerless samples adopted")
	}
}

func TestTrafficOutboxConcurrentWritersAndSymlinkProtection(t *testing.T) {
	dir := t.TempDir()
	o, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for seq := int64(1); seq <= 20; seq++ {
		group.Add(1)
		go func(seq int64) {
			defer group.Done()
			if err := o.Put(outboxFixture(seq)); err != nil {
				t.Error(err)
			}
		}(seq)
	}
	group.Wait()
	status, err := o.Status()
	if err != nil || status.Pending != 20 {
		t.Fatal("concurrent enqueue lost samples")
	}
	target := filepath.Join(t.TempDir(), "external")
	if err = os.WriteFile(target, []byte("external data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, filepath.Join(dir, "0000000000000021.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = o.Peek(); !errors.Is(err, ErrTrafficOutboxCorrupt) {
		t.Fatal("symlink accepted")
	}
	raw, _ := os.ReadFile(target)
	if string(raw) != "external data" {
		t.Fatal("external target changed")
	}
}
