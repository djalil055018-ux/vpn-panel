//go:build integration && linux

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestTrafficDeliveryHTTPOutageAndRestartIntegration(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		name := "measured"
		if unavailable {
			name = "unavailable"
		}
		t.Run(name, func(t *testing.T) { testTrafficDeliveryHTTPOutageAndRestart(t, unavailable) })
	}
}

func testTrafficDeliveryHTTPOutageAndRestart(t *testing.T, unavailable bool) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone connection failed")
	}
	defer db.Close()
	var database string
	if db.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := db.CreateTenant(ctx, "CODEX-TRAFFIC-HTTP")
	check(err)
	defer db.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
	node, err := db.CreateNode(ctx, tenant.ID, "CODEX-TRAFFIC-HTTP-NODE", security.HashToken("http-fixture-bootstrap"))
	check(err)
	token := "traffic-http-fixture-credential"
	_, err = db.Pool.Exec(ctx, `UPDATE nodes SET agent_token_hash=$2 WHERE id=$1::uuid`, node.ID, security.HashToken(token))
	check(err)
	client, err := db.CreateVPNClient(ctx, tenant.ID, "CODEX-TRAFFIC-HTTP-CLIENT", nil)
	check(err)
	app := &application{store: db}
	handler := app.requireAgent(app.receiveTrafficDelivery)
	var mode atomic.Int32
	mode.Store(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 1 {
			w.WriteHeader(503)
			return
		}
		if mode.CompareAndSwap(2, 0) {
			// Commit in the real handler, then drop the connection before any response.
			response := httptest.NewRecorder()
			handler(response, r)
			if response.Code != 204 {
				w.WriteHeader(response.Code)
				return
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		handler(w, r)
	}))
	defer server.Close()
	transport := agent.NewClient(server.URL)
	dir := t.TempDir()
	queue, err := agent.NewTrafficOutbox(dir, node.ID)
	check(err)
	sample := func(sequence, bytes int64, epoch string) model.TrafficDelivery {
		return model.TrafficDelivery{RecordedAt: time.Now().UTC(), Snapshot: model.ClientTrafficSnapshot{Sequence: sequence, Epoch: epoch, Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: bytes, ActiveIPsUnavailable: unavailable}}}}
	}
	first := sample(1, 100, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	check(queue.Put(first))
	worker := agent.NewTrafficWorker(queue, transport, token, nil)
	if worker.Drain(ctx, 16) == nil {
		t.Fatal("outage was ignored")
	}
	status, err := queue.Status()
	check(err)
	if status.Pending != 1 {
		t.Fatal("outage lost queue")
	}
	mode.Store(2)
	if worker.Drain(ctx, 16) == nil {
		t.Fatal("lost response acknowledged")
	}
	usage, err := db.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 100 {
		t.Fatal("request did not commit before lost response")
	}
	if (usage.ActiveIPs == nil) != unavailable {
		t.Fatal("HTTP commit lost address availability")
	}
	reopened, err := agent.NewTrafficOutbox(dir, node.ID)
	check(err)
	check(reopened.Put(sample(2, 150, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")))
	check(reopened.Put(sample(3, 30, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")))
	restarted := agent.NewTrafficWorker(reopened, transport, token, nil)
	check(restarted.Drain(ctx, 16))
	usage, err = db.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 180 {
		t.Fatalf("replay/runtime reset total=%d", usage.UsedBytes)
	}
	if (usage.ActiveIPs == nil) != unavailable {
		t.Fatal("restart replay changed address availability")
	}
	status, err = reopened.Status()
	check(err)
	if status.Pending != 0 {
		t.Fatal("acknowledged queue not empty")
	}
	if transport.SendTrafficDelivery(ctx, "wrong-fixture-credential", sample(4, 900, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")) == nil {
		t.Fatal("unauthorized delivery accepted")
	}
	usage, err = db.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 180 {
		t.Fatal("unauthorized traffic was charged")
	}
}
