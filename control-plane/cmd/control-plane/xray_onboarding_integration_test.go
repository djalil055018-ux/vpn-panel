//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestNativeXrayOnboardingHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer db.Close()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var name string
	check(db.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&name))
	if !strings.HasPrefix(name, "vpn_codex_test_delete_") {
		t.Fatal("refusing non-test database")
	}
	tenant, err := db.CreateTenant(ctx, "Native onboarding regression")
	check(err)
	bootstrap := security.HashToken("synthetic-native-onboarding-bootstrap")
	node, err := db.CreateNodeForRuntime(ctx, tenant.ID, "Native onboarding", bootstrap, "xray")
	check(err)
	app := &application{store: db, adminToken: "synthetic-native-onboarding-owner"}
	mux := http.NewServeMux()
	app.registerXrayOnboardingRoutes(mux)
	request := func(id string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/nodes/"+id+"/initialize-xray", strings.NewReader(`{}`))
		if authorized {
			r.Header.Set("Authorization", "Bearer "+app.adminToken)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := request(node.ID, false); w.Code != 401 {
		t.Fatalf("unauthorized status %d", w.Code)
	}
	if w := request("invalid", true); w.Code != 400 {
		t.Fatalf("invalid node status %d", w.Code)
	}
	if w := request(node.ID, true); w.Code != 409 {
		t.Fatalf("unregistered node status %d", w.Code)
	}
	_, err = db.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-native-onboarding-agent"), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
	check(err)
	release, err := db.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/native-onboarding.zip", SHA256: strings.Repeat("b", 64), Channel: "testing"})
	check(err)
	if w := request(node.ID, true); w.Code != 409 {
		t.Fatalf("unapproved core status %d", w.Code)
	}
	var generations, deployments int
	check(db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM desired_states WHERE node_id=$1::uuid),(SELECT count(*) FROM deployments WHERE node_id=$1::uuid)`, node.ID).Scan(&generations, &deployments))
	if generations != 0 || deployments != 0 {
		t.Fatal("failed onboarding published a generation")
	}
	check(db.ApproveCoreRelease(ctx, release.ID))
	const callers = 6
	responses := make(chan *httptest.ResponseRecorder, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); responses <- request(node.ID, true) }()
	}
	wg.Wait()
	close(responses)
	created := 0
	for w := range responses {
		if w.Code != 200 && w.Code != 202 {
			t.Fatalf("onboarding status %d", w.Code)
		}
		var result struct {
			Generation int64  `json:"generation"`
			Changed    bool   `json:"changed"`
			Version    string `json:"version"`
		}
		check(json.Unmarshal(w.Body.Bytes(), &result))
		if result.Generation != 1 || result.Version != "26.9.9" || result.Changed != (w.Code == 202) {
			t.Fatal("inconsistent onboarding response")
		}
		if result.Changed {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent onboarding created %d deployments", created)
	}
	state, exists, err := db.LatestDesiredState(ctx, node.ID)
	check(err)
	if !exists || state.Generation != 1 || state.XrayProfile != nil || len(state.Services) != 0 || state.Core.SHA256 != release.SHA256 {
		t.Fatal("native initial state changed")
	}
	before, err := json.Marshal(state)
	check(err)
	if w := request(node.ID, true); w.Code != 200 {
		t.Fatalf("retry status %d", w.Code)
	}
	after, exists, err := db.LatestDesiredState(ctx, node.ID)
	check(err)
	wire, err := json.Marshal(after)
	check(err)
	if !exists || string(before) != string(wire) {
		t.Fatal("retry replaced immutable desired state")
	}
	check(db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM desired_states WHERE node_id=$1::uuid),(SELECT count(*) FROM deployments WHERE node_id=$1::uuid)`, node.ID).Scan(&generations, &deployments))
	if generations != 1 || deployments != 1 {
		t.Fatal("native onboarding retry duplicated history")
	}
}
