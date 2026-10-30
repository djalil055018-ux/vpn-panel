package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

type typedTerminalDriver struct {
	*fakeTerminalDriver
	core string
}

func (d typedTerminalDriver) CoreType() string { return d.core }
func TestLeaseHealthSendsSelectedRuntimeCore(t *testing.T) {
	for _, core := range []string{"xray", "hysteria2"} {
		t.Run(core, func(t *testing.T) {
			reports := make(chan model.HealthReport, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var report model.HealthReport
				if json.NewDecoder(r.Body).Decode(&report) != nil {
					w.WriteHeader(400)
					return
				}
				reports <- report
				w.WriteHeader(204)
			}))
			defer server.Close()
			driver := typedTerminalDriver{&fakeTerminalDriver{healthy: true, version: "fixture-version"}, core}
			if err := sendLeaseSupervisorHealth(context.Background(), agent.NewClient(server.URL), driver, agent.SystemInfo{}, &agent.LocalState{AgentToken: "fixture-token", AppliedGeneration: 7}, true, "healthy"); err != nil {
				t.Fatal(err)
			}
			report := <-reports
			if report.Core != core || report.CoreVersion != "fixture-version" || report.AppliedGeneration != 7 {
				t.Fatal("health report lost selected runtime identity")
			}
		})
	}
}
func TestCertificateRefreshRoutesToActiveDriverAndHonorsCancellation(t *testing.T) {
	calls := 0
	failure := errors.New("fixture refresh failure")
	refresh := func(ctx context.Context, id, domain string) error {
		calls++
		if id != "certificate-id" || domain != "domain.invalid" {
			t.Fatal("certificate identity changed")
		}
		return failure
	}
	if err := refreshCertificateRuntime(context.Background(), refresh, "certificate-id", "domain.invalid"); !errors.Is(err, failure) || calls != 1 {
		t.Fatal("driver failure lost")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := refreshCertificateRuntime(cancelled, refresh, "certificate-id", "domain.invalid"); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled grant reached driver")
	}
	if err := refreshCertificateRuntime(context.Background(), nil, "certificate-id", "domain.invalid"); !errors.Is(err, errCertificateRuntime) {
		t.Fatal("missing active driver silently defaulted")
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := refreshCertificateRuntime(ctx, func(context.Context, string, string) error { stop(); return nil }, "certificate-id", "domain.invalid"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled refresh reported success")
	}
}
func TestCertificateWorkerRejectsMissingDriverBeforeACMEOrFileChanges(t *testing.T) {
	base := t.TempDir()
	_, err := obtainCertificateWithRuntime(context.Background(), base, model.CertificateJobGrant{}, nil)
	if !errors.Is(err, errCertificateRuntime) {
		t.Fatal("missing driver reached certificate issuance")
	}
	files, err := os.ReadDir(base)
	if err != nil || len(files) != 0 {
		t.Fatal("unconfigured certificate worker wrote files")
	}
}
