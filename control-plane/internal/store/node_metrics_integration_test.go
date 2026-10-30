//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func TestNodeMetricsIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("isolated database required")
	}
	defer p.Close()
	var database string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	var tenant, node string
	if err = p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('CODEX-METRICS') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant)
	if err = p.Pool.QueryRow(ctx, `INSERT INTO nodes(tenant_id,name,status) VALUES($1::uuid,'CODEX-METRICS-NODE','online') RETURNING id::text`, tenant).Scan(&node); err != nil {
		t.Fatal(err)
	}
	report := model.HealthReport{Healthy: true, CheckedAt: time.Now().UTC(), Metrics: &model.NodeMetrics{CPUPercent: 10, Load1: .5, MemoryTotal: 1000, MemoryUsed: 500, DiskTotal: 2000, DiskUsed: 750, NetworkRX: 100, NetworkTX: 200, UptimeSeconds: 300}}
	if err = p.SaveHealth(ctx, node, report); err != nil {
		t.Fatal(err)
	}
	report.Metrics.CPUPercent = 20
	if err = p.SaveHealth(ctx, node, report); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM node_metric_samples WHERE node_id=$1::uuid`, node).Scan(&count); err != nil || count != 1 {
		t.Fatalf("one-minute upsert count=%d err=%v", count, err)
	}
	_, err = p.Pool.Exec(ctx, `INSERT INTO node_metric_samples(node_id,sample_bucket,sampled_at,cpu_percent,load_1,memory_total_bytes,memory_used_bytes,disk_total_bytes,disk_used_bytes,network_rx_bytes,network_tx_bytes,uptime_seconds) VALUES($1::uuid,1,now()-interval '10 minutes',40,2,1000,750,2000,1000,90,180,290),($1::uuid,2,now()-interval '32 days',1,0,1000,1,2000,1,1,1,1)`, node)
	if err != nil {
		t.Fatal(err)
	}
	series, err := p.ListNodeMetrics(ctx, node, time.Now().Add(-time.Hour), time.Now().Add(time.Minute), 60)
	if err != nil || len(series.Points) != 2 {
		t.Fatalf("points=%d err=%v", len(series.Points), err)
	}
	if err = p.SaveHealth(ctx, node, report); err != nil {
		t.Fatal(err)
	}
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM node_metric_samples WHERE node_id=$1::uuid AND sampled_at<now()-interval '31 days'`, node).Scan(&count); err != nil || count != 0 {
		t.Fatalf("retention count=%d err=%v", count, err)
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	if _, err = p.ListNodeMetrics(scoped, node, time.Now().Add(-time.Hour), time.Now(), 60); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant principal read infrastructure metrics")
	}
	if _, err = p.ListNodeMetrics(ctx, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", time.Now().Add(-time.Hour), time.Now(), 60); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing node was not hidden")
	}
}
