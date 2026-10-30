package monitoring

import (
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func healthySnapshot() model.OperationsStatus {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	b := &model.BackupStatus{Status: "verified", LastSuccessAt: &now, LastVerifiedAt: &now, ReportedAt: &now, FreeBytes: 4 << 30}
	return model.OperationsStatus{GeneratedAt: now, ControlPlaneFreeBytes: 4 << 30, ControlPlaneBackup: b, Nodes: []model.OperationsNode{{ID: "node-a", Name: "Node A", Backup: b, Lifecycle: model.NodeLifecycleStatus{Registered: true, Online: true, Healthy: true, HealthFresh: true, DesiredGeneration: 1, AppliedGeneration: 1}}}}
}

func TestTrafficDeliveryMonitoring(t *testing.T) {
	s := healthySnapshot()
	s.Nodes[0].TrafficDelivery = &model.TrafficDeliveryReceipt{}
	rules := Evaluate(s)
	if len(rules) != 1 || rules[0].Rule != "traffic_delivery_delayed" || rules[0].GraceSeconds != 120 {
		t.Fatal("missing initial delivery warning")
	}
	s.Nodes[0].TrafficDelivery.RecordedAt = &s.GeneratedAt
	s.Nodes[0].TrafficDelivery.ReceivedAt = &s.GeneratedAt
	if len(Evaluate(s)) != 0 {
		t.Fatal("current traffic delivery alerted")
	}
	old := s.GeneratedAt.Add(-6 * time.Minute)
	s.Nodes[0].TrafficDelivery.RecordedAt = &old
	if len(Evaluate(s)) != 1 {
		t.Fatal("old backlog did not alert despite recent receipt")
	}
	s.Nodes[0].Lifecycle.Online = false
	for _, rule := range Evaluate(s) {
		if rule.Rule == "traffic_delivery_delayed" {
			t.Fatal("offline node duplicated traffic incident")
		}
	}
}
func TestWebhookMonitoringRules(t *testing.T) {
	s := healthySnapshot()
	old := s.GeneratedAt.Add(-91 * time.Second)
	s.WebhookQueue = &model.WebhookQueueStatus{LastDispatchAt: &old}
	if len(Evaluate(s)) != 0 {
		t.Fatal("unused webhook integration alerted")
	}
	s.WebhookQueue.EnabledEndpoints = 1
	s.WebhookQueue.PendingDeliveries = 2
	s.WebhookQueue.OverdueDeliveries = 1
	s.WebhookQueue.FailedDeliveries = 1
	rules := map[string]int{}
	for _, o := range Evaluate(s) {
		rules[o.Rule] = o.GraceSeconds
	}
	if len(rules) != 3 || rules["webhook_queue_stalled"] != 120 {
		t.Fatal("webhook incident rules missing")
	}
	s.WebhookQueue.LastDispatchAt = &s.GeneratedAt
	s.WebhookQueue.OverdueDeliveries = 0
	s.WebhookQueue.FailedDeliveries = 0
	if len(Evaluate(s)) != 0 {
		t.Fatal("healthy worker or scheduled retry alerted")
	}
}
func TestMonitoringRules(t *testing.T) {
	s := healthySnapshot()
	if len(Evaluate(s)) != 0 {
		t.Fatal("healthy baseline alerts")
	}
	s.Nodes[0].Lifecycle.Online = false
	s.Nodes[0].Lifecycle.AppliedGeneration = 0
	s.PendingAccessNodes = 1
	got := Evaluate(s)
	rules := map[string]int{}
	for _, o := range got {
		rules[o.Rule] = o.GraceSeconds
	}
	if rules["node_offline"] != 60 || rules["node_not_converged"] != 300 || rules["access_revocation_pending"] != 120 || len(rules) != 3 {
		t.Fatal("grace policy mismatch")
	}
	s = healthySnapshot()
	s.Nodes[0].Lifecycle.Registered = false
	s.Nodes[0].Backup = nil
	if len(Evaluate(s)) != 0 {
		t.Fatal("unregistered node alerted")
	}
	s = healthySnapshot()
	old := s.GeneratedAt.Add(-37 * time.Hour)
	s.ControlPlaneBackup = &model.BackupStatus{Status: "verified", LastSuccessAt: &old, LastVerifiedAt: &old}
	s.ExpiredCertificates = 1
	s.ControlPlaneFreeBytes = 0
	got = Evaluate(s)
	if len(got) != 3 {
		t.Fatal("backup certificate disk alerts missing")
	}
	s = healthySnapshot()
	s.ControlPlaneBackup = &model.BackupStatus{Status: "failed"}
	got = Evaluate(s)
	if len(got) != 1 || got[0].Rule != "backup_failed" || got[0].Severity != "critical" {
		t.Fatal("failed first backup not critical")
	}
}

func TestNodeResourceRulesUseFreshMetrics(t *testing.T) {
	s := healthySnapshot()
	s.Nodes[0].Metrics = &model.NodeMetricPoint{SampledAt: s.GeneratedAt, CPUPercent: 96, MemoryTotal: 100, MemoryUsed: 95, DiskTotal: 2 << 30, DiskUsed: (2 << 30) - (512 << 20)}
	rules := map[string]int{}
	for _, observation := range Evaluate(s) {
		rules[observation.Rule] = observation.GraceSeconds
	}
	if rules["node_cpu_high"] != 600 || rules["node_memory_high"] != 300 || rules["disk_low"] != 0 || len(rules) != 3 {
		t.Fatalf("resource rules mismatch: %+v", rules)
	}
	s.Nodes[0].Metrics.SampledAt = s.GeneratedAt.Add(-3 * time.Minute)
	s.Nodes[0].Backup.FreeBytes = 4 << 30
	if len(Evaluate(s)) != 0 {
		t.Fatal("stale metrics alerted")
	}
}

func TestClientDeviceWarning(t *testing.T) {
	s := healthySnapshot()
	s.ClientDeviceWarnings = []model.ClientDeviceUsage{{ClientID: "client-a", ClientName: "Client A", ActiveIPs: 3, DeviceLimit: 2}}
	got := Evaluate(s)
	if len(got) != 1 || got[0].Rule != "client_device_limit_exceeded" || got[0].Resource != "client-a" || got[0].GraceSeconds != 120 || got[0].Severity != "warning" {
		t.Fatalf("unexpected device warning: %+v", got)
	}
}
