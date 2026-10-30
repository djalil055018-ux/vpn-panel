package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

var ErrWebhookLimit = errors.New("maximum 20 webhook endpoints per tenant")

const webhookEndpointColumns = `id::text,tenant_id::text,name,url,events,enabled,created_at`

func scanWebhookEndpoint(row pgx.Row) (model.WebhookEndpoint, error) {
	var e model.WebhookEndpoint
	err := row.Scan(&e.ID, &e.TenantID, &e.Name, &e.URL, &e.Events, &e.Enabled, &e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return e, err
}
func (p *Postgres) CreateWebhookEndpoint(ctx context.Context, e model.WebhookEndpoint, encrypted string) (model.WebhookEndpoint, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return e, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return e, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockTenantAccess(ctx, tx, e.TenantID); err != nil {
		return e, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM webhook_endpoints WHERE tenant_id=$1::uuid`, e.TenantID).Scan(&count); err != nil {
		return e, err
	}
	if count >= 20 {
		return e, ErrWebhookLimit
	}
	e, err = scanWebhookEndpoint(tx.QueryRow(ctx, `INSERT INTO webhook_endpoints(id,tenant_id,name,url,events,secret_ciphertext) SELECT $1::uuid,id,$3,$4,$5,$6 FROM tenants WHERE id=$2::uuid RETURNING `+webhookEndpointColumns, e.ID, e.TenantID, e.Name, e.URL, e.Events, encrypted))
	if err != nil {
		return e, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'webhook.endpoint_created','admin','control-plane',jsonb_build_object('endpoint_id',$2::text))`, e.TenantID, e.ID)
	if err != nil {
		return e, err
	}
	return e, tx.Commit(ctx)
}
func (p *Postgres) ListWebhookEndpoints(ctx context.Context, tenant string) ([]model.WebhookEndpoint, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+webhookEndpointColumns+` FROM webhook_endpoints WHERE tenant_id=$1::uuid ORDER BY created_at DESC`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.WebhookEndpoint{}
	for rows.Next() {
		e, err := scanWebhookEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (p *Postgres) SetWebhookEnabled(ctx context.Context, id string, enabled bool) (model.WebhookEndpoint, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return model.WebhookEndpoint{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.WebhookEndpoint{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	e, err := scanWebhookEndpoint(tx.QueryRow(ctx, `UPDATE webhook_endpoints SET enabled=$2,updated_at=now() WHERE id=$1::uuid RETURNING `+webhookEndpointColumns, id, enabled))
	if err != nil {
		return e, err
	}
	if !enabled {
		_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status='cancelled',completed_at=now() WHERE endpoint_id=$1::uuid AND status='pending'`, id)
		if err != nil {
			return e, err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'webhook.endpoint_enabled_changed','admin','control-plane',jsonb_build_object('endpoint_id',$2::text,'enabled',$3::boolean))`, e.TenantID, id, enabled)
	if err != nil {
		return e, err
	}
	return e, tx.Commit(ctx)
}
func (p *Postgres) ListWebhookDeliveries(ctx context.Context, tenant string) ([]model.WebhookDelivery, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT d.id::text,d.endpoint_id::text,d.event_id::text,d.event_type,d.status,d.attempts,d.next_attempt_at,d.last_http_status,d.last_error,d.created_at,d.completed_at FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id=d.endpoint_id WHERE e.tenant_id=$1::uuid ORDER BY d.created_at DESC,d.id LIMIT 100`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.WebhookDelivery{}
	for rows.Next() {
		var d model.WebhookDelivery
		if err = rows.Scan(&d.ID, &d.EndpointID, &d.EventID, &d.EventType, &d.Status, &d.Attempts, &d.NextAttemptAt, &d.LastHTTPStatus, &d.LastError, &d.CreatedAt, &d.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (p *Postgres) DeleteWebhookEndpoint(ctx context.Context, id string) error {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,enabled FROM webhook_endpoints WHERE id=$1::uuid FOR UPDATE`, id).Scan(&tenant, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if enabled {
		return ErrBillingConflict
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM webhook_deliveries WHERE endpoint_id=$1::uuid AND status IN ('pending','delivering'))`, id).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrBillingConflict
	}
	if _, err = tx.Exec(ctx, `DELETE FROM webhook_endpoints WHERE id=$1::uuid`, id); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'webhook.endpoint_deleted','admin','control-plane',jsonb_build_object('endpoint_id',$2::text))`, tenant, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (p *Postgres) RetryWebhookDelivery(ctx context.Context, id string) error {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var status, tenant string
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT d.status,e.tenant_id::text,e.enabled FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id=d.endpoint_id WHERE d.id=$1::uuid FOR UPDATE OF d`, id).Scan(&status, &tenant, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enabled {
		return ErrBillingConflict
	}
	if status == "pending" {
		return tx.Commit(ctx)
	}
	if status != "failed" && status != "cancelled" {
		return ErrBillingConflict
	}
	_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status='pending',attempts=0,next_attempt_at=now(),completed_at=NULL,lease_token=NULL,lease_until=NULL WHERE id=$1::uuid`, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'webhook.delivery_retried','admin','control-plane',jsonb_build_object('delivery_id',$2::text))`, tenant, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (p *Postgres) ClaimWebhooks(ctx context.Context) ([]model.ClaimedWebhook, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return nil, ErrNotFound
	}
	if _, err := p.Pool.Exec(ctx, `DELETE FROM webhook_deliveries WHERE completed_at<now()-interval '90 days' AND status IN ('delivered','failed','cancelled')`); err != nil {
		return nil, err
	}
	// A crashed worker's final attempt becomes a visible terminal failure.
	_, err := p.Pool.Exec(ctx, `UPDATE webhook_deliveries SET status='failed',last_error='worker_lease_expired',completed_at=now() WHERE status='delivering' AND lease_until<now() AND attempts>=8`)
	if err != nil {
		return nil, err
	}
	_, err = p.Pool.Exec(ctx, `UPDATE webhook_deliveries d SET status='cancelled',completed_at=now() FROM webhook_endpoints e WHERE e.id=d.endpoint_id AND NOT e.enabled AND (d.status='pending' OR (d.status='delivering' AND d.lease_until<now()))`)
	if err != nil {
		return nil, err
	}
	rows, err := p.Pool.Query(ctx, `WITH picked AS (SELECT d.id FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id=d.endpoint_id WHERE e.enabled AND d.attempts<8 AND d.next_attempt_at<=now() AND (d.status='pending' OR (d.status='delivering' AND d.lease_until<now())) ORDER BY d.next_attempt_at,d.id FOR UPDATE OF d,e SKIP LOCKED LIMIT 4), claimed AS (UPDATE webhook_deliveries d SET status='delivering',attempts=attempts+1,lease_until=now()+interval '90 seconds',lease_token=gen_random_uuid() FROM picked p WHERE d.id=p.id RETURNING d.*) SELECT c.id::text,c.endpoint_id::text,c.event_id::text,e.url,e.secret_ciphertext,c.lease_token::text,c.payload,c.attempts FROM claimed c JOIN webhook_endpoints e ON e.id=c.endpoint_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ClaimedWebhook{}
	for rows.Next() {
		var d model.ClaimedWebhook
		if err = rows.Scan(&d.ID, &d.EndpointID, &d.EventID, &d.URL, &d.EncryptedSecret, &d.LeaseToken, &d.Payload, &d.Attempts); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (p *Postgres) FinishWebhook(ctx context.Context, d model.ClaimedWebhook, httpStatus int, category string) error {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return ErrNotFound
	}
	status := "pending"
	if category == "" {
		status = "delivered"
	} else if d.Attempts >= 8 {
		status = "failed"
	}
	delay := time.Minute * time.Duration(1<<min(d.Attempts-1, 6))
	if delay > time.Hour {
		delay = time.Hour
	}
	_, err := p.Pool.Exec(ctx, `UPDATE webhook_deliveries SET status=$3,last_http_status=NULLIF($4::integer,0),last_error=NULLIF($5,''),next_attempt_at=now()+($6::integer*interval '1 second'),lease_until=NULL,lease_token=NULL,completed_at=CASE WHEN $3 IN ('delivered','failed') THEN now() ELSE NULL END WHERE id=$1::uuid AND lease_token=$2::uuid AND status='delivering'`, d.ID, d.LeaseToken, status, httpStatus, category, int(delay.Seconds()))
	return err
}
