package agent

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"vpn-platform/internal/core/hysteria"
	"vpn-platform/internal/model"
)

var errHysteriaTraffic = errors.New("Hysteria traffic snapshot unavailable")
var hysteriaTrafficIdentity = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var runtimeInvocation = regexp.MustCompile(`^[0-9a-f]{32}$`)

type HysteriaTrafficCollector struct {
	statistics   *hysteria.Statistics
	epoch        func(context.Context) (string, error)
	nextSequence func() (int64, error)
	mu           sync.Mutex
	cached       *model.TrafficDelivery
	at           time.Time
}

// Invocation must read the managed runtime's durable process invocation identity,
// not the agent process or a desired-state generation. The sequence path is the
// same node-owned counter used by the durable outbox across agent/core restarts.
func NewHysteriaTrafficCollector(statistics *hysteria.Statistics, sequencePath string, invocation func(context.Context) (string, error)) (*HysteriaTrafficCollector, error) {
	if statistics == nil || invocation == nil || sequencePath == "" || !filepath.IsAbs(sequencePath) {
		return nil, errHysteriaTraffic
	}
	return &HysteriaTrafficCollector{statistics: statistics, epoch: invocation, nextSequence: func() (int64, error) { return reserveTrafficSequence(sequencePath) }}, nil
}
func cloneTrafficDelivery(value *model.TrafficDelivery) *model.TrafficDelivery {
	if value == nil {
		return nil
	}
	out := *value
	out.Snapshot = *cloneTrafficSnapshot(&value.Snapshot)
	return &out
}
func (c *HysteriaTrafficCollector) Collect(parent context.Context, force bool) (*model.TrafficDelivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.cached != nil && time.Since(c.at) < 30*time.Second {
		return cloneTrafficDelivery(c.cached), nil
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	before, err := c.epoch(ctx)
	if err != nil || !runtimeInvocation.MatchString(before) || before == strings.Repeat("0", 32) {
		return nil, errHysteriaTraffic
	}
	sequence, err := c.nextSequence()
	if err != nil || sequence <= 0 {
		return nil, errHysteriaTraffic
	}
	counts, err := c.statistics.Traffic(ctx)
	if err != nil {
		return nil, errHysteriaTraffic
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		if !hysteriaTrafficIdentity.MatchString(id) {
			return nil, errHysteriaTraffic
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	clients := make([]model.ClientTraffic, 0, len(ids))
	for _, id := range ids {
		count := counts[id]
		clients = append(clients, model.ClientTraffic{ClientID: id, Uplink: int64(count.UploadBytes), Downlink: int64(count.DownloadBytes), ActiveIPsUnavailable: true})
	}
	// The upstream /online count is a number of connections, not distinct IPs.
	// Do not substitute it into ActiveIPs; per-IP telemetry remains unavailable.
	after, err := c.epoch(ctx)
	if err != nil || before != after {
		return nil, errHysteriaTraffic
	}
	c.at = time.Now().UTC()
	c.cached = &model.TrafficDelivery{RecordedAt: c.at, Snapshot: model.ClientTrafficSnapshot{Epoch: before, Sequence: sequence, Clients: clients}}
	return cloneTrafficDelivery(c.cached), nil
}
