//go:build integration

package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestWebhookQueueHealthIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("isolated database required")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	baseline, err := p.WebhookQueueStatus(ctx)
	check(err)
	var tenant, endpoint string
	check(p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('CODEX-WEBHOOK-HEALTH') RETURNING id::text`).Scan(&tenant))
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant)
	check(p.Pool.QueryRow(ctx, `INSERT INTO webhook_endpoints(id,tenant_id,name,url,events,enabled,secret_ciphertext) VALUES(gen_random_uuid(),$1::uuid,'health','https://example.invalid/receiver',ARRAY['billing.invoice_paid'],true,'secret-marker-never-return') RETURNING id::text`, tenant).Scan(&endpoint))
	_, err = p.Pool.Exec(ctx, `INSERT INTO webhook_deliveries(endpoint_id,event_id,event_type,payload,status,next_attempt_at,lease_until) SELECT $1::uuid,gen_random_uuid(),'billing.invoice_paid','{}',v.status,v.next_at,v.lease FROM (VALUES ('pending',now()+interval '1 hour',NULL::timestamptz),('pending',now()-interval '4 minutes',NULL::timestamptz),('delivering',now(),now()-interval '4 minutes'),('failed',now(),NULL::timestamptz),('delivered',now(),NULL::timestamptz)) v(status,next_at,lease)`, endpoint)
	check(err)
	check(p.RecordWebhookDispatcherSuccess(ctx))
	q, err := p.WebhookQueueStatus(ctx)
	check(err)
	if q.EnabledEndpoints != baseline.EnabledEndpoints+1 || q.PendingDeliveries != baseline.PendingDeliveries+3 || q.OverdueDeliveries != baseline.OverdueDeliveries+2 || q.FailedDeliveries != baseline.FailedDeliveries+1 || q.LastDispatchAt == nil {
		t.Fatal("queue counts or worker heartbeat wrong")
	}
	raw, _ := json.Marshal(q)
	if strings.Contains(string(raw), "secret-marker") || strings.Contains(string(raw), "example.invalid") {
		t.Fatal("private endpoint data leaked")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE webhook_endpoints SET enabled=false WHERE id=$1::uuid`, endpoint)
	check(err)
	q, err = p.WebhookQueueStatus(ctx)
	check(err)
	if q.PendingDeliveries != baseline.PendingDeliveries || q.OverdueDeliveries != baseline.OverdueDeliveries || q.FailedDeliveries != baseline.FailedDeliveries {
		t.Fatal("disabled endpoint caused alerts")
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	if _, err = p.WebhookQueueStatus(scoped); err != ErrNotFound {
		t.Fatal("tenant read global queue")
	}
	if err = p.RecordWebhookDispatcherSuccess(scoped); err != ErrNotFound {
		t.Fatal("tenant forged worker heartbeat")
	}
}
