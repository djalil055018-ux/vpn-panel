package store

import (
	"context"
	"time"
	"vpn-platform/internal/model"
)

func (p *Postgres) RecordWebhookDispatcherSuccess(ctx context.Context) error {
	if _, ok := TenantPrincipal(ctx); ok {
		return ErrNotFound
	}
	_, err := p.Pool.Exec(ctx, `INSERT INTO webhook_dispatcher_runs(id,last_success_at) VALUES(true,clock_timestamp()) ON CONFLICT(id) DO UPDATE SET last_success_at=GREATEST(webhook_dispatcher_runs.last_success_at,EXCLUDED.last_success_at)`)
	return err
}
func (p *Postgres) WebhookQueueStatus(ctx context.Context) (model.WebhookQueueStatus, error) {
	out := model.WebhookQueueStatus{GeneratedAt: time.Now().UTC()}
	if _, ok := TenantPrincipal(ctx); ok {
		return out, ErrNotFound
	}
	err := p.Pool.QueryRow(ctx, `SELECT (SELECT last_success_at FROM webhook_dispatcher_runs WHERE id),
 (SELECT count(*) FROM webhook_endpoints WHERE enabled),
 count(*) FILTER(WHERE d.status IN ('pending','delivering')),
 count(*) FILTER(WHERE (d.status='pending' AND d.next_attempt_at<now()-interval '3 minutes') OR (d.status='delivering' AND d.lease_until<now()-interval '3 minutes')),
 count(*) FILTER(WHERE d.status='failed')
 FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id=d.endpoint_id WHERE e.enabled`).Scan(&out.LastDispatchAt, &out.EnabledEndpoints, &out.PendingDeliveries, &out.OverdueDeliveries, &out.FailedDeliveries)
	return out, err
}
