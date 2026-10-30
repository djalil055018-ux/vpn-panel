// Native lifecycle probe; run only in a new owned network namespace.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
	"vpn-platform/internal/core/wireguard"
	"vpn-platform/internal/model"
)

func main() {
	base := flag.String("base", "", "owned private synthetic root")
	flag.Parse()
	report := map[string]any{"status": "RUNNING", "production_changes": 0, "http_payload_tested_by_this_probe": false}
	checks := []string{}
	defer func() {
		if recover() != nil {
			report["status"] = "FAIL"
		}
		report["checks"] = checks
		json.NewEncoder(os.Stdout).Encode(report)
	}()
	check := func(label string, e error) {
		if e != nil {
			report["failed_check"] = label
			panic("probe failed")
		}
		checks = append(checks, label)
	}
	if os.Geteuid() != 0 || *base == "" {
		panic("owned root required")
	}
	// The controller creates a new network namespace before execution. Refuse
	// any inherited physical link, interface or network policy.
	ifs, e := net.Interfaces()
	check("interface_inventory", e)
	if len(ifs) != 1 || ifs[0].Name != "lo" {
		panic("empty network namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	check("provision_reviewed_amneziawg", wireguard.ProvisionAmneziaWG(ctx, *base))
	driver, e := wireguard.OpenAmneziaWG(ctx, *base)
	check("open_managed_runtime", e)
	defer driver.Close()
	key := func() string {
		var b [32]byte
		if _, e := rand.Read(b[:]); e != nil {
			panic("random unavailable")
		}
		return base64.StdEncoding.EncodeToString(b[:])
	}
	id := func() string {
		var b [16]byte
		rand.Read(b[:])
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
	}
	server, client, psk := key(), key(), key()
	pub, e := model.WireGuardPublicKey(client)
	check("synthetic_peer_key", e)
	spec, e := model.NewAmneziaWGSpec("3.1")
	check("version_settings", e)
	clientID := id()
	state := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: "amneziawg", Version: model.AmneziaWGNativeVersion, DownloadURL: model.AmneziaWGDownloadURL, SHA256: model.AmneziaWGArtifactSHA256}, Services: []model.ServiceSpec{{ID: id(), Protocol: "amneziawg", Transport: "udp", Security: "amneziawg", Listen: "0.0.0.0", Port: 51821, WireGuard: &model.WireGuardSpec{PrivateKey: server}, AmneziaWG: spec, Clients: []model.ClientSpec{{ID: clientID, StatsKey: clientID, WireGuard: &model.WireGuardPeer{PublicKey: pub, PresharedKey: psk, Address: "10.66.0.2/32"}}}}}}
	check("apply_initial_generation", driver.Reconcile(ctx, state))
	healthy, e := driver.Health()
	check("initial_health", e)
	if !healthy || driver.CoreType() != "amneziawg" || driver.CurrentVersion() != model.AmneziaWGNativeVersion {
		panic("runtime identity mismatch")
	}
	readProcess := func() string {
		data, e := os.ReadFile(filepath.Join(*base, "amneziawg/process.json"))
		check("private_process_receipt", e)
		return string(data)
	}
	before := readProcess()
	epoch, _, e := driver.Traffic(ctx)
	check("durable_traffic_epoch", e)
	state.Generation = 2
	state.Services[0].Clients = nil
	check("revoke_last_peer_without_restart", driver.Reconcile(ctx, state))
	if readProcess() != before {
		panic("membership update restarted daemon")
	}
	state.Generation = 3
	copySpec := *spec
	copySpec.Jc++
	state.Services[0].AmneziaWG = &copySpec
	check("replace_runtime_on_parameter_change", driver.Reconcile(ctx, state))
	if readProcess() == before {
		panic("parameter change did not replace daemon")
	}
	got, _, e := driver.Traffic(ctx)
	check("traffic_survives_replacement", e)
	if got != epoch {
		panic("traffic epoch reset")
	}
	stale := state
	stale.Generation = 2
	if driver.Reconcile(ctx, stale) == nil {
		panic("stale generation accepted")
	}
	checks = append(checks, "stale_generation_rejected")
	check("close_managed_runtime", driver.Close())
	if _, e = net.InterfaceByName(wireguard.InterfaceName); e == nil {
		panic("interface left after close")
	}
	if _, e = os.Stat(filepath.Join(*base, "amneziawg/process.json")); !errors.Is(e, os.ErrNotExist) {
		panic("process receipt left after close")
	}
	driver, e = wireguard.OpenAmneziaWG(ctx, *base)
	check("reopen_after_close", e)
	check("restore_same_committed_generation", driver.Reconcile(ctx, state))
	check("final_close", driver.Close())
	report["status"] = "PASS"
	report["managed_lifecycle_tested"] = true
}
