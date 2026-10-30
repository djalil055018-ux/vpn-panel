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

func TestBillingIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing production database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	const tenant = "68e8e76d-3f16-4ad0-8e91-8a4888a1ad80"
	const sweden = "45851736-7be9-43f2-bae2-725822b35bfa"
	const poland = "dd3e9553-1d04-46ef-84f2-12bf27b48b4a"
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Billing integration", "codex-billing-integration", true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant, "CODEX-BILLING-INTEGRATION", nil)
	check(err)
	badClient, err := p.CreateVPNClient(ctx, tenant, "CODEX-BILLING-BAD-CLIENT", nil)
	check(err)
	defer func() {
		for _, query := range []string{`DELETE FROM billing_invoices WHERE plan_id=$1::uuid`, `DELETE FROM billing_offers WHERE plan_id=$1::uuid`, `DELETE FROM vpn_access_plans WHERE id=$1::uuid`} {
			_, _ = p.Pool.Exec(context.Background(), query, plan.ID)
		}
		_, _ = p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id IN($1::uuid,$2::uuid)`, client.ID, badClient.ID)
	}()
	for _, service := range []string{sweden, poland} {
		_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service, true)
		check(err)
	}
	offer, err := p.CreateBillingOffer(ctx, tenant, model.BillingOffer{PlanID: plan.ID, Name: "Thirty days", AmountMinor: 1000, Currency: "RUB", DurationDays: 30, Enabled: true})
	check(err)
	invoice, created, err := p.CreateBillingInvoice(ctx, tenant, offer.ID, client.ID, "billing-idempotent-first")
	check(err)
	if !created {
		t.Fatal("first invoice not created")
	}
	repeated, created, err := p.CreateBillingInvoice(ctx, tenant, offer.ID, client.ID, "billing-idempotent-first")
	check(err)
	if created || repeated.ID != invoice.ID {
		t.Fatal("idempotency duplicated invoice")
	}
	_, _, err = p.CreateBillingInvoice(ctx, tenant, offer.ID, badClient.ID, "billing-idempotent-first")
	if !errors.Is(err, ErrBillingConflict) {
		t.Fatal("idempotency accepted changed request")
	}
	checkDesired := func(want int) {
		t.Helper()
		var count int
		check(p.Pool.QueryRow(ctx, `SELECT count(DISTINCT n.id) FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,jsonb_array_elements(ds.document->'services') s,jsonb_array_elements(s->'clients') u WHERE u->>'id'=$1`, client.VLESSUUID).Scan(&count))
		if count != want {
			t.Fatalf("client node presence %d want %d", count, want)
		}
	}
	generation := func() int64 {
		var n int64
		check(p.Pool.QueryRow(ctx, `SELECT sum(desired_generation) FROM nodes`).Scan(&n))
		return n
	}
	checkDesired(0)
	offer.AmountMinor = 1200
	offer.DurationDays = 60
	offer, err = p.UpdateBillingOffer(ctx, offer.ID, offer)
	check(err)
	pay := BillingPayment{InvoiceID: invoice.ID, Reference: "test-payment-1", Source: "webhook", EventID: "test-billing-event-1", PayloadHash: strings.Repeat("a", 64), AmountMinor: 1001, Currency: "RUB"}
	_, err = p.SettleBillingInvoice(ctx, pay)
	if !errors.Is(err, ErrBillingAmountMismatch) {
		t.Fatal("wrong amount accepted")
	}
	pay.AmountMinor = 1000
	result, err := p.SettleBillingInvoice(ctx, pay)
	check(err)
	if !result.Changed || len(result.Rebuilds) != 2 || result.Invoice.DurationDays != 30 || result.Invoice.AmountMinor != 1000 {
		t.Fatal("invoice snapshot or fulfillment incorrect")
	}
	checkDesired(2)
	expires := *result.Invoice.EntitlementExpiresAt
	generationBefore := generation()
	replay, err := p.SettleBillingInvoice(ctx, pay)
	check(err)
	if replay.Changed || !replay.Invoice.EntitlementExpiresAt.Equal(expires) || generation() != generationBefore {
		t.Fatal("duplicate payment changed entitlement")
	}
	pay.PayloadHash = strings.Repeat("b", 64)
	_, err = p.SettleBillingInvoice(ctx, pay)
	if !errors.Is(err, ErrBillingConflict) {
		t.Fatal("event payload changed")
	}
	second, _, err := p.CreateBillingInvoice(ctx, tenant, offer.ID, client.ID, "billing-renewal-second")
	check(err)
	extended, err := p.SettleBillingInvoice(ctx, BillingPayment{InvoiceID: second.ID, Reference: "manual-2", Source: "manual", AmountMinor: 1200, Currency: "RUB"})
	check(err)
	if len(extended.Rebuilds) != 0 || !extended.Invoice.EntitlementExpiresAt.Equal(expires.Add(60*24*time.Hour)) {
		t.Fatal("renewal did not extend existing period exactly once")
	}
	_, err = p.VoidBillingInvoice(ctx, second.ID)
	if !errors.Is(err, ErrBillingConflict) {
		t.Fatal("paid invoice voided")
	}
	// A paid client participates in ordinary plan changes without manual grants.
	off := false
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &off})
	check(err)
	checkDesired(0)
	on := true
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &on})
	check(err)
	checkDesired(2)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, poland, false)
	check(err)
	checkDesired(1)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, poland, true)
	check(err)
	checkDesired(2)
	// Expiration removes only paid access; a manual direct grant remains valid.
	_, err = p.Pool.Exec(ctx, `INSERT INTO vpn_client_services(tenant_id,client_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, client.ID, sweden)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE billing_entitlements SET expires_at=now()-interval '1 second' WHERE client_id=$1::uuid AND plan_id=$2::uuid`, client.ID, plan.ID)
	check(err)
	_, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	checkDesired(1)
	generationBefore = generation()
	_, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if generation() != generationBefore {
		t.Fatal("expired entitlement repeatedly rebuilt")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_services WHERE client_id=$1::uuid`, client.ID).Scan(&count))
	if count != 1 {
		t.Fatal("manual access removed")
	}
	// Broken target rolls back payment, event deduplication, entitlement and nodes.
	var badNode, badService string
	check(p.Pool.QueryRow(ctx, `INSERT INTO nodes(tenant_id,name) VALUES($1::uuid,'CODEX-BILLING-BAD-NODE') RETURNING id::text`, tenant).Scan(&badNode))
	defer p.Pool.Exec(context.Background(), `DELETE FROM nodes WHERE id=$1::uuid`, badNode)
	check(p.Pool.QueryRow(ctx, `INSERT INTO vpn_services(tenant_id,node_id,name,protocol,port,transport,security,enabled) VALUES($1::uuid,$2::uuid,'bad','vless',19499,'tcp','reality',true) RETURNING id::text`, tenant, badNode).Scan(&badService))
	_, err = p.Pool.Exec(ctx, `INSERT INTO vpn_access_plan_services(tenant_id,plan_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, plan.ID, badService)
	check(err)
	broken, _, err := p.CreateBillingInvoice(ctx, tenant, offer.ID, badClient.ID, "billing-broken-target")
	check(err)
	generationBefore = generation()
	_, err = p.SettleBillingInvoice(ctx, BillingPayment{InvoiceID: broken.ID, Reference: "bad-event", Source: "webhook", EventID: "billing-bad-event", PayloadHash: strings.Repeat("c", 64), AmountMinor: 1200, Currency: "RUB"})
	if err == nil {
		t.Fatal("broken target accepted")
	}
	if generation() != generationBefore {
		t.Fatal("partial node generations committed")
	}
	stillPending, err := p.GetBillingInvoice(ctx, broken.ID)
	check(err)
	if stillPending.Status != "pending" {
		t.Fatal("payment committed despite rebuild failure")
	}
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_payment_events WHERE event_id='billing-bad-event'`).Scan(&count))
	if count != 0 {
		t.Fatal("failed event consumed")
	}
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_entitlements WHERE client_id=$1::uuid`, badClient.ID).Scan(&count))
	if count != 0 {
		t.Fatal("failed entitlement committed")
	}
}
