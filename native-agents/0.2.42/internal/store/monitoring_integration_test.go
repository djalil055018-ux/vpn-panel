//go:build integration

package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestMonitoringIncidentLifecycleIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("isolated DB required")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live DB")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = p.Pool.Exec(ctx, `DELETE FROM monitoring_incidents;DELETE FROM monitoring_runs`)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM monitoring_incidents;DELETE FROM monitoring_runs;DELETE FROM audit_events WHERE event_type='monitoring.incident_acknowledged'`)
	at := time.Now().UTC()
	o := []model.IncidentObservation{{Rule: "node_offline", Resource: "codex-test-node", ResourceName: "Isolated test", Severity: "warning", GraceSeconds: 60}}
	check(p.SyncMonitoringIncidents(ctx, o, at))
	s, err := p.MonitoringStatus(ctx)
	check(err)
	if len(s.Incidents) != 0 {
		t.Fatal("opened before grace")
	}
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(60*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if len(s.Incidents) != 1 || s.OpenCount != 1 {
		t.Fatal("not opened after grace")
	}
	id := s.Incidents[0].ID
	ack, err := p.AcknowledgeMonitoringIncident(ctx, id)
	check(err)
	if ack.AcknowledgedAt == nil {
		t.Fatal("ack not stored")
	}
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(120*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if len(s.Incidents) != 1 || s.Incidents[0].AcknowledgedAt == nil {
		t.Fatal("duplicate or lost acknowledgement")
	}
	o[0].Severity = "critical"
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(180*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if s.CriticalCount != 1 || s.Incidents[0].AcknowledgedAt != nil {
		t.Fatal("escalation did not clear acknowledgement")
	}
	// An old overlapping scan must not resolve a newer critical observation.
	check(p.SyncMonitoringIncidents(ctx, nil, at.Add(150*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if s.OpenCount != 1 {
		t.Fatal("old scan resolved newer incident")
	}
	malformed := append(o, o[0])
	if p.SyncMonitoringIncidents(ctx, malformed, at.Add(240*time.Second)) == nil {
		t.Fatal("duplicate observation accepted")
	}
	check(p.SyncMonitoringIncidents(ctx, nil, at.Add(240*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if s.OpenCount != 0 || s.Incidents[0].ResolvedAt == nil {
		t.Fatal("recovery not recorded")
	}
	if _, err = p.AcknowledgeMonitoringIncident(ctx, id); err != ErrNotFound {
		t.Fatal("resolved incident acknowledged")
	}
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(300*time.Second)))
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(360*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if s.OpenCount != 1 || len(s.Incidents) != 2 || s.Incidents[0].ID == id {
		t.Fatal("recurrence missing new incident")
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: "68e8e76d-3f16-4ad0-8e91-8a4888a1ad80", Role: "operator"})
	if _, err = p.MonitoringStatus(scoped); err != ErrNotFound {
		t.Fatal("tenant read global incidents")
	}
	if p.SyncMonitoringIncidents(scoped, nil, at.Add(400*time.Second)) != ErrNotFound {
		t.Fatal("tenant changed monitor")
	}
	// A gap in successful scans resets the grace period of a pending condition.
	check(p.SyncMonitoringIncidents(ctx, nil, at.Add(420*time.Second)))
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(480*time.Second)))
	check(p.SyncMonitoringIncidents(ctx, o, at.Add(700*time.Second)))
	s, err = p.MonitoringStatus(ctx)
	check(err)
	if s.OpenCount != 0 {
		t.Fatal("failed scan gap counted as continuous observation")
	}
}
