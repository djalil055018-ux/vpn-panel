//go:build linux

package hysteria

import (
	"context"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/model"
)

func TestValidatorRejectsPrivilegedOverflowAndCancelledExecution(t *testing.T) {
	i, release := testInstaller(t, testELF(62), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("validator must never download") }))
	state := model.DesiredState{Core: release}
	for _, ids := range [][2]int{{0, 65534}, {65534, 0}, {-1, 1}, {1, -1}, {int(math.MaxInt32) + 1, 65534}, {65534, int(math.MaxInt32) + 1}} {
		if i.Validate(context.Background(), state, ids[0], ids[1]) == nil {
			t.Fatal("invalid runtime identity accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if i.Validate(ctx, state, 65534, 65534) == nil {
		t.Fatal("cancelled validation accepted")
	}
	if i.Validate(context.Background(), state, 65534, 65534) == nil {
		t.Fatal("missing verified binary accepted")
	}
	entries, _ := os.ReadDir(i.base)
	if len(entries) != 0 {
		t.Fatal("rejected validation changed filesystem")
	}
}
func TestValidatorChecksOriginalListenerBeforeStaging(t *testing.T) {
	raw := testELF(62)
	i, release := testInstaller(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
	if _, err := i.Install(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	state := model.DesiredState{Core: release, Services: []model.ServiceSpec{{ID: "33333333-3333-4333-8333-333333333333", Protocol: "hysteria2", Transport: "udp", Security: "tls", Listen: "invalid-listener", Port: 443, TLS: &model.TLSSpec{CertificateID: tlsFixtureID, ServerName: "tls-probe.invalid", CertificateFile: "/not-used/certificate", KeyFile: "/not-used/key"}}}}
	if i.Validate(context.Background(), state, 65534, 65534) == nil {
		t.Fatal("original invalid listener hidden by loopback override")
	}
	if _, err := os.Lstat(filepath.Join(i.base, "hysteria2")); !os.IsNotExist(err) {
		t.Fatal("invalid config created native preflight files")
	}
}
