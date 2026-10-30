//go:build integration

package store

import (
	"context"
	"testing"
)

// Called by the real store fixtures for PPTP, native and Xray WireGuard, and
// OpenVPN. Each fixture also checks its native desired peers/CRL and delivery.
func assertNativeContinuousQuota(t *testing.T, p *Postgres, ctx context.Context, clientID string, assertAccess func(int)) {
	t.Helper()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, err := p.Pool.Exec(ctx, `INSERT INTO vpn_client_continuous_quotas(client_id,limit_bytes,baseline_bytes,baseline_at) VALUES($1::uuid,10,11,now()-interval '40 days')`, clientID)
	check(err)
	_, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	assertAccess(0)
	usage, err := p.VPNClientUsage(ctx, clientID)
	check(err)
	if usage.UsedBytes != 11 || !usage.QuotaExceeded {
		t.Fatal("native continuous quota ignored")
	}
	_, err = p.SetVPNClientContinuousLimit(ctx, clientID, 20)
	check(err)
	assertAccess(1)
	_, err = p.SetVPNClientContinuousLimit(ctx, clientID, 10)
	check(err)
	assertAccess(0)
	_, err = p.SetVPNClientContinuousLimit(ctx, clientID, 0)
	check(err)
	assertAccess(1)
}
