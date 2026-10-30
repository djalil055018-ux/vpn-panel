package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"vpn-platform/internal/core/hysteria"
)

func TestHysteriaTrafficEpochDirectionCacheAndSequence(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"%s":{"tx":123,"rx":456789}}`, id)
	}))
	defer s.Close()
	stats, e := hysteria.NewStatistics(s.Listener.Addr().(*net.TCPAddr).Port, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal("statistics setup failed")
	}
	epoch := strings.Repeat("a", 32)
	calls := 0
	reader := func(context.Context) (string, error) { calls++; return epoch, nil }
	c, e := NewHysteriaTrafficCollector(stats, filepath.Join(t.TempDir(), "sequence"), reader)
	if e != nil {
		t.Fatal("collector setup failed")
	}
	sequence := int64(0)
	c.nextSequence = func() (int64, error) { sequence++; return sequence, nil }
	first, e := c.Collect(context.Background(), false)
	if e != nil || first.Snapshot.Epoch != epoch || first.Snapshot.Sequence != 1 || len(first.Snapshot.Clients) != 1 || first.Snapshot.Clients[0].Uplink != 123 || first.Snapshot.Clients[0].Downlink != 456789 {
		t.Fatal("runtime snapshot or directions incorrect")
	}
	first.Snapshot.Clients[0].Uplink = 999
	if !first.Snapshot.Clients[0].ActiveIPsUnavailable || first.Snapshot.Clients[0].ActiveIPs != 0 {
		t.Fatal("unsupported address telemetry was reported as measured")
	}
	first.Snapshot.Clients[0].ActiveIPsUnavailable = false
	cached, e := c.Collect(context.Background(), false)
	if e != nil || cached.Snapshot.Clients[0].Uplink != 123 || !cached.Snapshot.Clients[0].ActiveIPsUnavailable || calls != 2 {
		t.Fatal("cache was mutated or recollected")
	}
	epoch = strings.Repeat("b", 32)
	fresh, e := c.Collect(context.Background(), true)
	if e != nil || fresh.Snapshot.Sequence != 2 || fresh.Snapshot.Epoch != epoch {
		t.Fatal("forced epoch collection failed")
	}
	reads := 0
	c.epoch = func(context.Context) (string, error) {
		reads++
		if reads%2 == 0 {
			return strings.Repeat("c", 32), nil
		}
		return epoch, nil
	}
	if value, e := c.Collect(context.Background(), true); e != errHysteriaTraffic || value != nil {
		t.Fatal("mixed runtime epochs accepted")
	}
	c.epoch = reader
	c.nextSequence = func() (int64, error) { return 0, errors.New("unavailable") }
	if value, e := c.Collect(context.Background(), true); e != errHysteriaTraffic || value != nil {
		t.Fatal("missing durable sequence accepted")
	}
}
func TestHysteriaCollectorRejectsWrongClientIdentity(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"not-a-platform-client":{"tx":1,"rx":2}}`))
	}))
	defer s.Close()
	stats, _ := hysteria.NewStatistics(s.Listener.Addr().(*net.TCPAddr).Port, strings.Repeat("a", 32))
	c, _ := NewHysteriaTrafficCollector(stats, filepath.Join(t.TempDir(), "sequence"), func(context.Context) (string, error) { return strings.Repeat("a", 32), nil })
	c.nextSequence = func() (int64, error) { return 1, nil }
	if value, e := c.Collect(context.Background(), true); e != errHysteriaTraffic || value != nil {
		t.Fatal("unknown client identity accepted")
	}
	if _, e := NewTrafficWorkerWithCollector(nil, nil, "", nil, nil); e == nil {
		t.Fatal("missing runtime collector accepted")
	}
}
