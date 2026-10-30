package main

import (
	"math"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func TestTrafficSnapshotMetadata(t *testing.T) {
	if !validTrafficSnapshot(nil) {
		t.Fatal("legacy health must remain valid")
	}
	valid := model.ClientTrafficSnapshot{Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Sequence: 1}
	if !validTrafficSnapshot(&valid) {
		t.Fatal("valid snapshot rejected")
	}
	for _, sample := range []model.ClientTrafficSnapshot{
		{Epoch: valid.Epoch, Sequence: 0},
		{Epoch: valid.Epoch, Sequence: -1},
		{Epoch: valid.Epoch, Sequence: 9000000000000001},
		{Epoch: "00000000000000000000000000000000", Sequence: 1},
		{Epoch: "invalid", Sequence: 1},
		{Epoch: valid.Epoch, Sequence: 1, Clients: []model.ClientTraffic{{ClientID: "invalid"}}},
	} {
		if validTrafficSnapshot(&sample) {
			t.Fatal("invalid snapshot accepted")
		}
	}
}

func TestMetricWindow(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		value    string
		duration time.Duration
		step     int
	}{{"", 24 * time.Hour, 300}, {"1h", time.Hour, 60}, {"24h", 24 * time.Hour, 300}, {"7d", 7 * 24 * time.Hour, 1800}, {"30d", 30 * 24 * time.Hour, 7200}} {
		from, step, ok := metricWindow(test.value, now)
		if !ok || step != test.step || now.Sub(from) != test.duration {
			t.Fatalf("range=%q from=%v step=%d ok=%v", test.value, from, step, ok)
		}
	}
	if _, _, ok := metricWindow("year", now); ok {
		t.Fatal("unsupported metric range accepted")
	}
}

func TestValidNodeMetrics(t *testing.T) {
	valid := &model.NodeMetrics{CPUPercent: 50, Load1: 1.5, MemoryTotal: 100, MemoryUsed: 90, DiskTotal: 200, DiskUsed: 100, NetworkRX: 1, NetworkTX: 2, UptimeSeconds: 3}
	if !validNodeMetrics(nil) || !validNodeMetrics(valid) {
		t.Fatal("valid metrics rejected")
	}
	invalid := []model.NodeMetrics{*valid, *valid, *valid, *valid, *valid}
	invalid[0].CPUPercent = 101
	invalid[1].Load1 = math.Inf(1)
	invalid[2].MemoryUsed = 101
	invalid[3].DiskUsed = -1
	invalid[4].NetworkTX = -1
	for _, value := range invalid {
		if validNodeMetrics(&value) {
			t.Fatal("invalid metrics accepted")
		}
	}
}

func TestValidClientTraffic(t *testing.T) {
	valid := []model.ClientTraffic{{ClientID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Uplink: 10, Downlink: 20, ActiveIPs: 2}}
	if !validClientTraffic(nil) || !validClientTraffic(valid) {
		t.Fatal("valid traffic rejected")
	}
	if !validClientTraffic([]model.ClientTraffic{{ClientID: valid[0].ClientID, Uplink: 12, ActiveIPsUnavailable: true}}) {
		t.Fatal("unavailable address telemetry rejected")
	}
	invalid := [][]model.ClientTraffic{
		{{ClientID: "bad", Uplink: 1}},
		{{ClientID: valid[0].ClientID, Uplink: -1}},
		{{ClientID: valid[0].ClientID, ActiveIPs: 10001}},
		{{ClientID: valid[0].ClientID, ActiveIPs: 1, ActiveIPsUnavailable: true}},
		{valid[0], valid[0]},
	}
	for _, samples := range invalid {
		if validClientTraffic(samples) {
			t.Fatalf("invalid traffic accepted: %+v", samples)
		}
	}
}
