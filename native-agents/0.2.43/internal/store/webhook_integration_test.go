//go:build integration

package store

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/webhook"
)

func TestWebhookOutboxIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
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
	var tenant string
	check(p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('CODEX-WEBHOOK-INTEGRATION') RETURNING id::text`).Scan(&tenant))
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Webhook plan", "webhook-plan", true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant, "Webhook client", nil)
	check(err)
	offer, err := p.CreateBillingOffer(ctx, tenant, model.BillingOffer{PlanID: plan.ID, Name: "Webhook offer", AmountMinor: 100, Currency: "RUB", DurationDays: 1, Enabled: true})
	check(err)
	id, err := webhook.NewID()
	check(err)
	master := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	encrypted, err := webhook.Encrypt(master, id, "test-webhook-secret")
	check(err)
	endpoint, err := p.CreateWebhookEndpoint(ctx, model.WebhookEndpoint{ID: id, TenantID: tenant, Name: "Isolated webhook", URL: "https://example.org/hook", Events: []string{"billing.invoice_paid", "billing.invoice_voided"}}, encrypted)
	check(err)
	if endpoint.Enabled {
		t.Fatal("new endpoint enabled")
	}
	createInvoice := func(key string) model.BillingInvoice {
		t.Helper()
		i, _, err := p.CreateBillingInvoice(ctx, tenant, offer.ID, client.ID, key)
		check(err)
		return i
	}
	disabledInvoice := createInvoice("disabled-webhook")
	_, err = p.VoidBillingInvoice(ctx, disabledInvoice.ID)
	check(err)
	rows, err := p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if len(rows) != 0 {
		t.Fatal("disabled endpoint enqueued")
	}
	_, err = p.SetWebhookEnabled(ctx, id, true)
	check(err)
	invoice := createInvoice("enabled-webhook")
	payment := BillingPayment{InvoiceID: invoice.ID, Reference: "webhook-test-" + invoice.ID, Source: "manual", AmountMinor: 100, Currency: "RUB"}
	_, err = p.SettleBillingInvoice(ctx, payment)
	check(err)
	_, err = p.SettleBillingInvoice(ctx, payment)
	check(err)
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if len(rows) != 1 {
		t.Fatal("outbox missing or duplicated")
	}
	deliveryID := rows[0].ID
	claimed, err := p.ClaimWebhooks(ctx)
	check(err)
	if len(claimed) != 1 || claimed[0].ID != deliveryID {
		t.Fatal("claim failed")
	}
	if strings.Contains(string(claimed[0].Payload), "payment_reference") || strings.Contains(string(claimed[0].Payload), "vless_uuid") {
		t.Fatal("sensitive fields in payload")
	}
	again, err := p.ClaimWebhooks(ctx)
	check(err)
	if len(again) != 0 {
		t.Fatal("lease claimed twice")
	}
	check(p.FinishWebhook(ctx, claimed[0], 503, "http_rejected"))
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if rows[0].Status != "pending" || rows[0].Attempts != 1 || rows[0].NextAttemptAt.Before(time.Now().Add(50*time.Second)) {
		t.Fatal("retry backoff missing")
	}
	_, err = p.SetWebhookEnabled(ctx, id, false)
	check(err)
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if rows[0].Status != "cancelled" {
		t.Fatal("disable did not cancel pending")
	}
	if p.RetryWebhookDelivery(ctx, deliveryID) != ErrBillingConflict {
		t.Fatal("retry disabled endpoint")
	}
	_, err = p.SetWebhookEnabled(ctx, id, true)
	check(err)
	check(p.RetryWebhookDelivery(ctx, deliveryID))
	check(p.RetryWebhookDelivery(ctx, deliveryID))
	fresh, err := p.ClaimWebhooks(ctx)
	check(err)
	if len(fresh) != 1 {
		t.Fatal("retry not claimable")
	}
	check(p.FinishWebhook(ctx, claimed[0], 204, ""))
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if rows[0].Status != "delivering" {
		t.Fatal("stale lease completed new attempt")
	}
	check(p.FinishWebhook(ctx, fresh[0], 204, ""))
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if rows[0].Status != "delivered" {
		t.Fatal("delivery not completed")
	}
	tx, err := p.Pool.Begin(ctx)
	check(err)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'billing.invoice_paid','admin','test',jsonb_build_object('invoice_id',$2::text))`, tenant, invoice.ID)
	check(err)
	check(tx.Rollback(ctx))
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if len(rows) != 1 {
		t.Fatal("rolled back event leaked into outbox")
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	if _, err = p.ListWebhookEndpoints(scoped, tenant); err != ErrNotFound {
		t.Fatal("tenant read integrations")
	}
	if p.DeleteWebhookEndpoint(ctx, id) != ErrBillingConflict {
		t.Fatal("enabled endpoint deleted")
	}
	_, err = p.SetWebhookEnabled(ctx, id, false)
	check(err)
	check(p.DeleteWebhookEndpoint(ctx, id))
	rows, err = p.ListWebhookDeliveries(ctx, tenant)
	check(err)
	if len(rows) != 0 {
		t.Fatal("deleted endpoint retained deliveries")
	}
}
