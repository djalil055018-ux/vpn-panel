//go:build integration

package store

import (
	"bytes"
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
)

type heldDeltaFixture struct {
	ctx             context.Context
	p               *Postgres
	tenant, id, sha string
	inv             map[string]any
	raw             []byte
	mappings        []RemnawaveImportClient
}

func deltaCheck(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func deltaBytes(t *testing.T, inv map[string]any) ([]byte, string) {
	t.Helper()
	raw, e := json.Marshal(inv)
	deltaCheck(t, e)
	_, r, e := remnawave.Parse(raw)
	deltaCheck(t, e)
	return raw, r.SHA256
}
func cloneDelta(t *testing.T, inv map[string]any) map[string]any {
	t.Helper()
	raw, e := json.Marshal(inv)
	deltaCheck(t, e)
	var out map[string]any
	deltaCheck(t, json.Unmarshal(raw, &out))
	return out
}
func newHeldDeltaFixture(t *testing.T) heldDeltaFixture {
	t.Helper()
	ctx, p := deletionStore(t)
	tenant, e := p.CreateTenant(ctx, "Held delta fixture")
	deltaCheck(t, e)
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	deltaCheck(t, e)
	var inv map[string]any
	deltaCheck(t, json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://delta-" + tenant.ID + ".example.test"
	for _, v := range inv["users"].([]any) {
		u := v.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		var id string
		deltaCheck(t, p.Pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id))
		u["vlessUuid"] = id
		deltaCheck(t, p.Pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id))
		u["uuid"] = id
	}
	raw, digest := deltaBytes(t, inv)
	staged, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, digest)
	deltaCheck(t, e)
	mappings, e := p.RemnawaveImportClients(ctx, staged.ID, 0, 250)
	deltaCheck(t, e)
	return heldDeltaFixture{ctx, p, tenant.ID, staged.ID, digest, inv, raw, mappings}
}
func advanceDelta(t *testing.T, inv map[string]any) map[string]any {
	t.Helper()
	next := cloneDelta(t, inv)
	at, e := time.Parse(time.RFC3339Nano, next["captured_at"].(string))
	deltaCheck(t, e)
	next["captured_at"] = at.Add(time.Second).Format(time.RFC3339Nano)
	return next
}
func (f heldDeltaFixture) apply(t *testing.T, inv map[string]any, base string) (RemnawaveDeltaApplied, error) {
	t.Helper()
	raw, digest := deltaBytes(t, inv)
	return f.p.ApplyRemnawaveHeldDelta(f.ctx, f.id, f.tenant, base, digest, raw)
}
func (f heldDeltaFixture) head(t *testing.T) string {
	t.Helper()
	var d string
	deltaCheck(t, f.p.Pool.QueryRow(f.ctx, `SELECT inventory_sha256 FROM remnawave_import_heads WHERE import_id=$1::uuid`, f.id).Scan(&d))
	return d
}

func TestRemnawaveHeldDeltaApplyIntegration(t *testing.T) {
	f := newHeldDeltaFixture(t)
	_, e := f.p.PrepareRemnawaveNoResetQuota(f.ctx, f.id, f.tenant, f.sha)
	deltaCheck(t, e)
	_, e = f.p.DeleteVPNClient(f.ctx, f.mappings[1].ClientID, f.mappings[1].Name)
	deltaCheck(t, e)
	next := advanceDelta(t, f.inv)
	users := next["users"].([]any)
	first := users[0].(map[string]any)
	first["username"] = "Changed source name"
	first["status"] = "DISABLED"
	first["expireAt"] = "2028-01-01T00:00:00Z"
	first["vlessUuid"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	first["trojanPassword"] = "rotated-private-fixture"
	first["userTraffic"].(map[string]any)["usedTrafficBytes"] = float64(200000)
	first["trafficLimitBytes"] = float64(123456789)
	next["hosts"] = map[string]any{"hosts": []any{map[string]any{"private": "fixture-host-metadata"}}}
	fourth := cloneDelta(t, users[2].(map[string]any))
	fourth["id"] = float64(4)
	fourth["uuid"] = "44444444-aaaa-4bbb-8ccc-dddddddddddd"
	fourth["vlessUuid"] = "44444444-4444-4444-8444-444444444444"
	fourth["shortUuid"] = "delta-fourth"
	fourth["username"] = "Fourth source user"
	next["users"] = []any{first, users[1], fourth}
	raw, digest := deltaBytes(t, next)
	result, e := f.apply(t, next, f.sha)
	deltaCheck(t, e)
	if !result.Applied || result.Created != 1 || result.Updated != 1 || result.Deleted != 1 || result.SourceAbsent != 1 || result.QuotasRefreshed != 1 || result.CutoverReady {
		t.Fatal("held delta counters differ")
	}
	replay, e := f.apply(t, next, f.sha)
	deltaCheck(t, e)
	if replay.Applied {
		t.Fatal("retry applied twice")
	}
	same, e := f.apply(t, next, digest)
	deltaCheck(t, e)
	if same.Applied {
		t.Fatal("current exact bytes applied twice")
	}
	var original, current []byte
	deltaCheck(t, f.p.Pool.QueryRow(f.ctx, `SELECT inventory FROM remnawave_imports WHERE id=$1::uuid`, f.id).Scan(&original))
	deltaCheck(t, f.p.Pool.QueryRow(f.ctx, `SELECT inventory FROM remnawave_inventory_revisions WHERE import_id=$1::uuid AND inventory_sha256=$2`, f.id, digest).Scan(&current))
	if !bytes.Equal(original, f.raw) || !bytes.Equal(current, raw) {
		t.Fatal("original or reviewed raw fields changed")
	}
	for _, q := range []string{`UPDATE remnawave_imports SET inventory=inventory WHERE id=$1::uuid`, `UPDATE remnawave_inventory_revisions SET inventory=inventory WHERE import_id=$1::uuid`} {
		if _, e = f.p.Pool.Exec(f.ctx, q, f.id); e == nil {
			t.Fatal("history allowed overwrite")
		}
	}
	usage, e := f.p.VPNClientUsage(f.ctx, f.mappings[0].ClientID)
	deltaCheck(t, e)
	if usage.ImportedBytes != 200000 || usage.UsedBytes != 200000 || usage.TrafficLimitBytes != 123456789 || usage.UplinkBytes != 0 || usage.DownlinkBytes != 0 {
		t.Fatal("quota refresh lost baseline")
	}
	mappings, e := f.p.RemnawaveImportClients(f.ctx, f.id, 0, 250)
	deltaCheck(t, e)
	if len(mappings) != 4 || !mappings[1].Deleted || !mappings[1].SourcePresent || mappings[2].SourcePresent || mappings[2].Deleted {
		t.Fatal("source absence and target tombstone collapsed")
	}
	prepared, e := f.p.PrepareRemnawaveNoResetQuota(f.ctx, f.id, f.tenant, digest)
	deltaCheck(t, e)
	if prepared.Prepared != 1 || prepared.Existing != 1 || prepared.Deleted != 1 {
		t.Fatal("quota preparation read original revision")
	}
	preview, e := f.p.PreviewRemnawaveDelta(f.ctx, f.id, f.tenant, raw)
	deltaCheck(t, e)
	if !preview.IdenticalBytes || preview.BeforeSHA256 != digest {
		t.Fatal("preview read stale head")
	}
	listed, e := f.p.ListRemnawaveImports(f.ctx)
	deltaCheck(t, e)
	found := false
	for _, i := range listed {
		if i.ID == f.id {
			found = i.Report.SHA256 == digest
		}
	}
	if !found {
		t.Fatal("list read original report")
	}
	// Source reappearance retains the prior target ID; a deleted target stays dead.
	back := advanceDelta(t, next)
	back["users"] = append(back["users"].([]any), cloneDelta(t, f.inv["users"].([]any)[2].(map[string]any)))
	back["verification"].(map[string]any)["source_total"] = float64(4)
	back["verification"].(map[string]any)["unique_user_ids"] = float64(4)
	_, e = f.apply(t, back, digest)
	deltaCheck(t, e)
	_, backSHA := deltaBytes(t, back)
	if _, e = f.apply(t, next, f.sha); !errors.Is(e, ErrRemnawaveBase) {
		t.Fatal("old accepted revision moved head backwards")
	}
	staged, created, e := f.p.StageRemnawaveInventory(f.ctx, f.tenant, mustDeltaBytes(t, back), backSHA)
	deltaCheck(t, e)
	if created || staged.Report.SHA256 != backSHA {
		t.Fatal("stage replay did not bind current head")
	}
	clients, e := f.p.ListVPNClients(f.ctx, f.tenant)
	deltaCheck(t, e)
	if len(clients) != 3 {
		t.Fatal("deleted client resurrected or source absence lost target")
	}
	for _, c := range clients {
		if !c.RemnawaveHold || c.Status != "disabled" {
			t.Fatal("delta activated client")
		}
	}
	var count int
	deltaCheck(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND event_type='remnawave.delta_applied'`, f.tenant).Scan(&count))
	if count != 2 {
		t.Fatal("retry emitted audit")
	}
	encoded, e := json.Marshal([]any{result, replay, preview, listed})
	deltaCheck(t, e)
	if bytes.Contains(encoded, []byte("rotated-private-fixture")) || bytes.Contains(encoded, []byte("fixture-host-metadata")) {
		t.Fatal("response exposed raw credentials")
	}
}
func mustDeltaBytes(t *testing.T, inv map[string]any) []byte {
	raw, _ := deltaBytes(t, inv)
	return raw
}

func TestRemnawaveHeldDeltaConflictIntegration(t *testing.T) {
	f := newHeldDeltaFixture(t)
	next := advanceDelta(t, f.inv)
	next["users"].([]any)[0].(map[string]any)["username"] = "Review a nonidentical revision"
	raw, digest := deltaBytes(t, next)
	for _, ctx := range []context.Context{WithAdminPrincipal(f.ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}}), WithAdminPrincipal(f.ctx, model.AdminSession{Account: model.AdminAccount{Role: "monitor"}}), WithTenantPrincipal(f.ctx, model.TenantAPIToken{TenantID: f.tenant, Role: "operator"})} {
		if _, e := f.p.ApplyRemnawaveHeldDelta(ctx, f.id, f.tenant, f.sha, digest, raw); !errors.Is(e, ErrNotFound) {
			t.Fatal("scope bypass")
		}
	}
	if _, e := f.p.ApplyRemnawaveHeldDelta(f.ctx, f.id, "00000000-0000-4000-8000-000000000001", f.sha, digest, raw); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign tenant applied")
	}
	if _, e := f.p.ApplyRemnawaveHeldDelta(f.ctx, f.id, f.tenant, f.sha, strings.Repeat("0", 64), raw); !errors.Is(e, ErrRemnawaveReview) {
		t.Fatal("unreviewed bytes applied")
	}
	if _, e := f.apply(t, next, strings.Repeat("0", 64)); !errors.Is(e, ErrRemnawaveBase) {
		t.Fatal("stale base applied")
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["source_origin"] = "https://other.example.test" },
		func(v map[string]any) { v["captured_at"] = f.inv["captured_at"] },
		func(v map[string]any) { v["captured_at"] = "2026-09-25T21:00:01Z" },
	} {
		v := cloneDelta(t, next)
		change(v)
		if _, e := f.apply(t, v, f.sha); !errors.Is(e, remnawave.ErrDeltaSource) {
			t.Fatal("wrong source or time applied")
		}
	}
	// A source identity can rotate credentials, but cannot be reused for a new ID.
	for _, field := range []string{"uuid", "createdAt", "id"} {
		v := cloneDelta(t, next)
		u := v["users"].([]any)[0].(map[string]any)
		switch field {
		case "uuid":
			u[field] = "99999999-9999-4999-8999-999999999999"
		case "createdAt":
			u[field] = "2026-02-01T00:00:00Z"
		case "id":
			u[field] = float64(999)
		}
		if _, e := f.apply(t, v, f.sha); !errors.Is(e, ErrRemnawaveConflict) {
			t.Fatal("historical identity reassigned: " + field)
		}
	}
	_, e := f.p.PrepareRemnawaveNoResetQuota(f.ctx, f.id, f.tenant, f.sha)
	deltaCheck(t, e)
	for _, q := range []string{
		`UPDATE vpn_clients SET name=name||' local edit' WHERE id=$1::uuid`,
		`UPDATE vpn_clients SET remnawave_hold=false WHERE id=$1::uuid`,
		`UPDATE vpn_client_continuous_quotas SET baseline_bytes=baseline_bytes+1 WHERE client_id=$1::uuid`,
		`UPDATE vpn_client_continuous_quotas SET uplink_bytes=1 WHERE client_id=$1::uuid`,
		`UPDATE vpn_client_continuous_quotas SET limit_bytes=limit_bytes+1 WHERE client_id=$1::uuid`,
	} {
		_, e = f.p.Pool.Exec(f.ctx, q, f.mappings[0].ClientID)
		deltaCheck(t, e)
		if _, e = f.apply(t, next, f.sha); !errors.Is(e, ErrRemnawaveConflict) {
			t.Fatal("target drift overwritten")
		}
		_, e = f.p.Pool.Exec(f.ctx, `UPDATE vpn_clients SET name=$2,remnawave_hold=true WHERE id=$1::uuid`, f.mappings[0].ClientID, f.mappings[0].Name)
		deltaCheck(t, e)
		_, e = f.p.Pool.Exec(f.ctx, `UPDATE vpn_client_continuous_quotas SET baseline_bytes=123456,uplink_bytes=0,limit_bytes=1000000000 WHERE client_id=$1::uuid`, f.mappings[0].ClientID)
		deltaCheck(t, e)
	}
	v := cloneDelta(t, next)
	v["users"].([]any)[0].(map[string]any)["trafficLimitStrategy"] = "MONTH"
	if _, e = f.apply(t, v, f.sha); !errors.Is(e, ErrTrafficPolicyConflict) {
		t.Fatal("prepared accounting policy changed silently")
	}
	if f.head(t) != f.sha {
		t.Fatal("failed application changed head")
	}
}

func TestRemnawaveHeldDeltaAtomicIntegration(t *testing.T) {
	f := newHeldDeltaFixture(t)
	_, e := f.p.PrepareRemnawaveNoResetQuota(f.ctx, f.id, f.tenant, f.sha)
	deltaCheck(t, e)
	next := advanceDelta(t, f.inv)
	next["users"].([]any)[0].(map[string]any)["username"] = "Rollback this name"
	next["users"].([]any)[0].(map[string]any)["userTraffic"].(map[string]any)["usedTrafficBytes"] = float64(200000)
	_, e = f.p.Pool.Exec(f.ctx, `CREATE FUNCTION fail_delta_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='remnawave.delta_applied' THEN RAISE EXCEPTION 'synthetic late failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_delta_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_delta_audit()`)
	deltaCheck(t, e)
	if _, e = f.apply(t, next, f.sha); e == nil {
		t.Fatal("late audit failure ignored")
	}
	_, e = f.p.Pool.Exec(f.ctx, `DROP TRIGGER fail_delta_audit ON audit_events; DROP FUNCTION fail_delta_audit()`)
	deltaCheck(t, e)
	if f.head(t) != f.sha {
		t.Fatal("failure committed head")
	}
	usage, e := f.p.VPNClientUsage(f.ctx, f.mappings[0].ClientID)
	deltaCheck(t, e)
	if usage.UsedBytes != 123456 {
		t.Fatal("failure committed baseline")
	}
	mappings, e := f.p.RemnawaveImportClients(f.ctx, f.id, 0, 250)
	deltaCheck(t, e)
	if mappings[0].Name != f.mappings[0].Name {
		t.Fatal("failure committed client")
	}
	var revisions int
	deltaCheck(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM remnawave_inventory_revisions WHERE import_id=$1::uuid`, f.id).Scan(&revisions))
	if revisions != 1 {
		t.Fatal("failure committed revision")
	}
	// Competing reviewed revisions share one base: exactly one may commit.
	alternate := cloneDelta(t, next)
	alternate["users"].([]any)[0].(map[string]any)["username"] = "Other competing name"
	var wg sync.WaitGroup
	var mu sync.Mutex
	applied, conflicts := 0, 0
	unexpected := []error{}
	for _, v := range []map[string]any{next, alternate} {
		wg.Add(1)
		go func(v map[string]any) {
			defer wg.Done()
			r, e := f.apply(t, v, f.sha)
			mu.Lock()
			defer mu.Unlock()
			if e == nil && r.Applied {
				applied++
			} else if errors.Is(e, ErrRemnawaveBase) {
				conflicts++
			} else {
				unexpected = append(unexpected, e)
			}
		}(v)
	}
	wg.Wait()
	if applied != 1 || conflicts != 1 || len(unexpected) > 0 {
		t.Fatal("concurrent stale write was not serialized")
	}
	// Whichever revision won, deleting its target then replaying cannot revive it.
	winner := next
	if f.head(t) != func() string { _, d := deltaBytes(t, next); return d }() {
		winner = alternate
	}
	mappings, e = f.p.RemnawaveImportClients(f.ctx, f.id, 0, 250)
	deltaCheck(t, e)
	_, e = f.p.DeleteVPNClient(f.ctx, mappings[0].ClientID, mappings[0].Name)
	deltaCheck(t, e)
	r, e := f.apply(t, winner, f.sha)
	deltaCheck(t, e)
	if r.Applied || r.Deleted != 1 {
		t.Fatal("post-delete retry resurrected target")
	}
}
