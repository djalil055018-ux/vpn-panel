//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
)

func deletionStore(t *testing.T) (context.Context, *Postgres) {
	t.Helper()
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
	t.Cleanup(cancel)
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var database string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_delete_") {
		t.Fatal("dedicated deletion test database required")
	}
	return ctx, p
}

func TestVPNClientDeleteIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Synthetic deletion")
	check(err)
	other, err := p.CreateTenant(ctx, "Foreign deletion tenant")
	check(err)
	_, _, err = p.ImportReviewedPPTP(ctx)
	check(err)
	check(p.ApproveReviewedPPTP(ctx))
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Удаляемый тестовый клиент", nil)
	check(err)
	survivor, err := p.CreateVPNClient(ctx, tenant.ID, "Surviving client", nil)
	check(err)
	nodes := []string{}
	services := []string{}
	for i, name := range []string{"first", "second"} {
		bootstrap := security.HashToken("delete-pptp-" + name)
		node, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Delete test "+name, bootstrap, "pptp")
		check(e)
		_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("delete-agent-"+name), "0.2.30", "ubuntu", "24.04", "amd64", "pptp")
		check(e)
		_, _, e = p.InitializePPTPRuntime(ctx, node.ID)
		check(e)
		address, port := "pptp-delete.example.test", 1723
		service, e := p.CreateVPNService(ctx, node.ID, "Delete service "+name, "pptp", "0.0.0.0", port, "tcp,gre", "mppe", &address, &port)
		check(e)
		_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
		check(e)
		_, e = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
		check(e)
		if i == 0 {
			_, e = p.AttachVPNClientAndRebuild(ctx, service.ID, survivor.ID)
			check(e)
		}
		nodes = append(nodes, node.ID)
		services = append(services, service.ID)
	}
	countDesired := func(id string) int {
		t.Helper()
		var n int
		check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states d ON d.node_id=n.id AND d.generation=n.desired_generation,jsonb_array_elements(d.document->'services') s,jsonb_array_elements(s->'clients') c WHERE c->>'stats_key'=$1 OR c->>'id'=$1`, id).Scan(&n))
		return n
	}
	if countDesired(client.ID) != 2 || countDesired(survivor.ID) != 1 {
		t.Fatal("initial access missing")
	}
	_, err = p.CreateVPNClientSubscription(ctx, client.ID, make([]byte, 16), 1, make([]byte, 32), "synthetic-delete")
	check(err)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "Delete billing plan", "delete-plan", true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, services[0], true)
	check(err)
	offer, err := p.CreateBillingOffer(ctx, tenant.ID, model.BillingOffer{PlanID: plan.ID, Name: "Delete offer", AmountMinor: 100, Currency: "RUB", DurationDays: 30, Enabled: true})
	check(err)
	paid, _, err := p.CreateBillingInvoice(ctx, tenant.ID, offer.ID, client.ID, "delete-paid-invoice")
	check(err)
	payment := BillingPayment{InvoiceID: paid.ID, Reference: "delete-paid-reference", Source: "synthetic", AmountMinor: 100, Currency: "RUB"}
	_, err = p.SettleBillingInvoice(ctx, payment)
	check(err)
	pending, _, err := p.CreateBillingInvoice(ctx, tenant.ID, offer.ID, client.ID, "delete-pending-invoice")
	check(err)
	foreign := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: other.ID, Role: "operator"})
	if _, err = p.DeleteVPNClient(foreign, client.ID, client.Name); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant deleted client")
	}
	if _, err = p.DeleteVPNClient(ctx, client.ID, "incorrect"); !errors.Is(err, ErrClientDeleteConfirmation) {
		t.Fatal("confirmation bypass")
	}
	// Legacy stale access can outlive a missing membership. Deletion must still
	// find native IDs/stats keys in the current desired document of the second node.
	_, err = p.Pool.Exec(ctx, `DELETE FROM vpn_client_services WHERE client_id=$1::uuid AND service_id=$2::uuid`, client.ID, services[1])
	check(err)
	if countDesired(client.ID) != 2 {
		t.Fatal("stale desired fixture missing")
	}
	// An affected generation save failure must revert invoice changes, keys,
	// memberships, subscription removal and deletion as one transaction.
	_, err = p.Pool.Exec(ctx, `CREATE FUNCTION codex_reject_delete_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic generation failure'; END $$; CREATE TRIGGER codex_reject_delete_generation BEFORE INSERT ON desired_states FOR EACH ROW EXECUTE FUNCTION codex_reject_delete_generation()`)
	check(err)
	if _, err = p.DeleteVPNClient(ctx, client.ID, client.Name); err == nil {
		t.Fatal("forced generation failure did not cancel deletion")
	}
	_, err = p.Pool.Exec(ctx, `DROP TRIGGER codex_reject_delete_generation ON desired_states; DROP FUNCTION codex_reject_delete_generation()`)
	check(err)
	_, err = p.GetVPNClient(ctx, client.ID)
	check(err)
	var n int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_pptp WHERE client_id=$1::uuid`, client.ID).Scan(&n))
	if n != 2 {
		t.Fatal("failed delete removed native keys")
	}
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_invoices WHERE client_id=$1::uuid AND deleted_client_id IS NULL`, client.ID).Scan(&n))
	if n != 2 {
		t.Fatal("failed delete changed invoice references")
	}
	result, err := p.DeleteVPNClient(ctx, client.ID, client.Name)
	check(err)
	if !result.Deleted || len(result.Rebuilds) != 2 || result.PreservedInvoices != 2 || result.VoidedInvoices != 1 || result.PreservedImport {
		t.Fatal("incorrect deletion receipt")
	}
	if countDesired(client.ID) != 0 || countDesired(survivor.ID) != 1 {
		t.Fatal("deletion left access or affected another client")
	}
	if _, err = p.GetVPNClient(ctx, client.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted client remains readable")
	}
	if _, err = p.SetVPNClientStatus(ctx, client.ID, "active"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted client can be enabled")
	}
	if _, err = p.DeleteVPNClient(ctx, client.ID, client.Name); !errors.Is(err, ErrNotFound) {
		t.Fatal("repeated deletion was not bounded")
	}
	for _, table := range []string{"vpn_client_pptp", "vpn_client_subscriptions", "vpn_client_services", "billing_entitlements"} {
		check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE client_id=$1::uuid`, client.ID).Scan(&n))
		if n != 0 {
			t.Fatal("live client records retained in " + table)
		}
	}
	invoices, err := p.ListBillingInvoices(ctx, tenant.ID)
	check(err)
	if len(invoices) != 2 {
		t.Fatal("invoice history was erased")
	}
	for _, invoice := range invoices {
		if !invoice.ClientDeleted || invoice.ClientID != client.ID {
			t.Fatal("historical invoice identity lost")
		}
		if invoice.ID == pending.ID && invoice.Status != "void" {
			t.Fatal("pending invoice not voided")
		}
		if invoice.ID == paid.ID && invoice.Status != "paid" {
			t.Fatal("paid invoice altered")
		}
	}
	settled, err := p.SettleBillingInvoice(ctx, payment)
	check(err)
	if settled.Changed {
		t.Fatal("payment replay resurrected access")
	}
	payment.InvoiceID = pending.ID
	payment.Reference = "pending-deleted-reference"
	if _, err = p.SettleBillingInvoice(ctx, payment); !errors.Is(err, ErrBillingConflict) {
		t.Fatal("deleted client's invoice settled")
	}
	// A delayed native traffic batch can still advance without recreating a client.
	err = p.SaveTrafficDelivery(ctx, nodes[0], model.TrafficDelivery{RecordedAt: time.Now(), Snapshot: model.ClientTrafficSnapshot{Epoch: strings.Repeat("a", 32), Sequence: 10, Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: 10, Downlink: 20}}}})
	check(err)
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='vpn_client.deleted' AND payload->>'client_id'=$1`, client.ID).Scan(&n))
	if n != 1 {
		t.Fatal("successful deletion audit differs")
	}
}

func TestVPNClientDeleteXrayIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	client, err := p.CreateVPNClient(ctx, tenant, "Synthetic Xray deletion", nil)
	check(err)
	for _, service := range services {
		_, err = p.AttachVPNClientAndRebuild(ctx, service, client.ID)
		check(err)
	}
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 2 {
		t.Fatal("Xray fixture access missing")
	}
	result, err := p.DeleteVPNClient(ctx, client.ID, client.Name)
	check(err)
	if len(result.Rebuilds) != 2 {
		t.Fatal("Xray deletion did not rebuild both nodes")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states d ON d.node_id=n.id AND d.generation=n.desired_generation WHERE d.document::text LIKE '%'||$1||'%'`, client.VLESSUUID).Scan(&count))
	if count != 0 {
		t.Fatal("Xray credential remains in active desired state")
	}
}

func TestVPNClientDeleteImportedIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Synthetic imported deletion")
	check(err)
	raw, err := os.ReadFile("../remnawave/testdata/inventory.json")
	check(err)
	_, report, err := remnawave.Parse(raw)
	check(err)
	imported, _, err := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(err)
	clients, err := p.ListVPNClients(ctx, tenant.ID)
	check(err)
	client := clients[0]
	admin := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}})
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	for _, restricted := range []context.Context{admin, operator} {
		if _, err = p.DeleteVPNClient(restricted, client.ID, client.Name); !errors.Is(err, ErrImportedClientDeleteOwner) {
			t.Fatal("imported deletion owner boundary bypassed")
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := p.DeleteVPNClient(ctx, client.ID, client.Name); results <- e }()
	}
	wg.Wait()
	close(results)
	success, missing := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrNotFound) {
			missing++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || missing != 1 {
		t.Fatal("concurrent deletion was not serialized")
	}
	mappings, err := p.RemnawaveImportClients(ctx, imported.ID, 0, 250)
	check(err)
	if len(mappings) != 3 {
		t.Fatal("import provenance lost")
	}
	deleted := 0
	for _, m := range mappings {
		if m.Deleted {
			deleted++
			if m.ClientID != client.ID || m.Name != client.Name || m.Held {
				t.Fatal("invalid deletion marker")
			}
		}
	}
	if deleted != 1 {
		t.Fatal("deleted marker count")
	}
	var saved []byte
	check(p.Pool.QueryRow(ctx, `SELECT inventory FROM remnawave_imports WHERE id=$1::uuid`, imported.ID).Scan(&saved))
	if string(saved) != string(raw) {
		t.Fatal("immutable source snapshot changed")
	}
	replay, created, err := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(err)
	if created || replay.ID != imported.ID {
		t.Fatal("replayed import recreated deleted client")
	}
	clients, err = p.ListVPNClients(ctx, tenant.ID)
	check(err)
	if len(clients) != 2 {
		t.Fatal("deleted imported client resurrected")
	}
	payload, _ := json.Marshal(mappings)
	for _, secret := range []string{"synthetic-trojan-credential", "synthetic-ss-credential", "subscriptionUrl"} {
		if strings.Contains(string(payload), secret) {
			t.Fatal("deletion history leaked credential")
		}
	}
}
