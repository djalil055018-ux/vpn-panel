package compiler

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

// Real Xray processes, synthetic credentials and loopback-only traffic. The TCP
// relay observes encrypted transit to the exit; only the exit can decrypt it.
func TestCascadeNativeTwoHopExitFailureAndRevocation(t *testing.T) {
	binary := os.Getenv("VPN_TEST_XRAY_BINARY")
	if binary == "" {
		t.Skip("set VPN_TEST_XRAY_BINARY for isolated real-core test")
	}
	for _, entryImported := range []bool{false, true} {
		for _, exitImported := range []bool{false, true} {
			name := fmt.Sprintf("entry-imported-%t/exit-imported-%t", entryImported, exitImported)
			t.Run(name, func(t *testing.T) { runCascadeNative(t, binary, entryImported, exitImported) })
		}
	}
}

func runCascadeNative(t *testing.T, binary string, entryImported, exitImported bool) {
	t.Helper()
	dir := t.TempDir()
	logDir := dir
	if root := os.Getenv("VPN_TEST_XRAY_DIAGNOSTIC_DIR"); root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		var err error
		logDir, err = os.MkdirTemp(root, "case-")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(logDir, "case.txt"), []byte(t.Name()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	port := func() int {
		t.Helper()
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	write := func(path string, b []byte) {
		t.Helper()
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	// A local TLS 1.3 destination supplies the REALITY handshake shape. The
	// authenticated tunnels validate REALITY keys; they do not bypass TLS checks.
	certKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(certKey)
	if e != nil {
		t.Fatal(e)
	}
	certificate, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if e != nil {
		t.Fatal(e)
	}
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "front") }))
	front.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, Certificates: []tls.Certificate{certificate}}
	front.StartTLS()
	defer front.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "cascade-native-ok") }))
	defer origin.Close()
	state := func(imported bool) (model.DesiredState, string) {
		t.Helper()
		s := cascadeFixture()
		s.XrayCascades = nil
		s.Services[0].Listen = "127.0.0.1"
		s.Services[0].Port = port()
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s.Services[0].Reality = &model.RealitySpec{Destination: front.Listener.Addr().String(), ServerName: "localhost", ShortID: "abcd", PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), SecretRef: "reality/" + cascadeServiceID}
		if imported {
			raw, err := compileXrayBase(s)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if json.Unmarshal(raw, &cfg) != nil {
				t.Fatal("fixture")
			}
			in := cfg["inbounds"].([]any)[0].(map[string]any)
			in["settings"].(map[string]any)["clients"] = []any{}
			raw, err = json.Marshal(map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}})
			if err != nil {
				t.Fatal(err)
			}
			profile, _, err := xrayprofile.Project(raw, []model.XrayProfileBinding{{ServiceID: cascadeServiceID, InboundTag: cascadeServiceID}})
			if err != nil {
				t.Fatal(err)
			}
			s.XrayProfile = profile
		}
		return s, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	entry, entryPublic := state(entryImported)
	exit, exitPublic := state(exitImported)
	exit.XrayCascades = &model.XrayCascadesSpec{Version: 1, Exits: []model.XrayCascadeExit{{ID: cascadeID, ServiceID: cascadeServiceID, ClientID: cascadeTransitID}}}
	exitPort := exit.Services[0].Port
	// This relay cannot turn a failed exit into a direct connection to origin.
	relay, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	var transitBytes atomic.Int64
	go func() {
		for {
			a, err := relay.Accept()
			if err != nil {
				return
			}
			go func() {
				defer a.Close()
				b, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", exitPort), time.Second)
				if err != nil {
					return
				}
				defer b.Close()
				a.SetDeadline(time.Now().Add(15 * time.Second))
				b.SetDeadline(time.Now().Add(15 * time.Second))
				go func() { io.Copy(a, b); a.Close() }()
				n, _ := io.Copy(b, a)
				transitBytes.Add(n)
			}()
		}
	}()
	exitFlow := ""
	if exitImported {
		exitFlow = "xtls-rprx-vision"
	}
	cascadePort := port()
	entry.XrayCascades = &model.XrayCascadesSpec{Version: 1, Entries: []model.XrayCascadeEntry{{ID: cascadeID, ServiceID: cascadeServiceID, Port: cascadePort, Clients: append([]model.ClientSpec{}, entry.Services[0].Clients...), Exit: model.XrayCascadeEndpoint{Address: "127.0.0.1", Port: relay.Addr().(*net.TCPAddr).Port, ClientID: cascadeTransitID, ServerName: "localhost", PublicKey: exitPublic, ShortID: "abcd", Fingerprint: "firefox", Flow: exitFlow}}}}
	compile := func(name string, s model.DesiredState) string {
		t.Helper()
		raw, err := CompileXray(s)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if json.Unmarshal(raw, &cfg) != nil {
			t.Fatal("fixture")
		}
		// Give each test process its own API socket; compiled VPN routing and
		// credentials are unchanged. Restrict DIRECT to this loopback origin.
		cfg["api"].(map[string]any)["listen"] = fmt.Sprintf("127.0.0.1:%d", port())
		for _, v := range cfg["outbounds"].([]any) {
			out := v.(map[string]any)
			if out["tag"] == "DIRECT" {
				out["settings"] = map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1"}, "port": origin.Listener.Addr().(*net.TCPAddr).Port}}}
			}
		}
		raw, err = json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		write(path, raw)
		return path
	}
	start := func(path string, p int) func() {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, "run", "-config", path)
		log, err := os.CreateTemp(logDir, filepath.Base(path)+"-*.log")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				cmd.Process.Kill()
				cmd.Wait()
				log.Close()
			}
		}
		t.Cleanup(stop)
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 100*time.Millisecond)
			if err == nil {
				c.Close()
				return stop
			}
			time.Sleep(25 * time.Millisecond)
		}
		stop()
		t.Fatal("isolated Xray failed to listen; private fixture log retained only until test cleanup")
		return stop
	}
	stopExit := start(compile("exit", exit), exitPort)
	stopEntry := start(compile("entry", entry), entry.Services[0].Port)
	client := func(name string, target int) *http.Client {
		t.Helper()
		proxyPort := port()
		user := map[string]any{"id": cascadeClientID, "encryption": "none"}
		if entryImported {
			user["flow"] = "xtls-rprx-vision"
		}
		cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": proxyPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": target, "users": []any{user}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": "localhost", "fingerprint": "firefox", "password": entryPublic, "shortId": "abcd"}}}}}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		write(path, raw)
		start(path, proxyPort)
		u, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort))
		tr := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 4 * time.Second}
	}
	direct, cascade := client("ordinary-client", entry.Services[0].Port), client("cascade-client", cascadePort)
	probe := func(c *http.Client) bool {
		res, err := c.Get(origin.URL)
		if err != nil {
			return false
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode == 200 && string(body) == "cascade-native-ok"
	}
	if !probe(direct) {
		t.Fatal("ordinary profile unavailable before cascade test")
	}
	if !probe(cascade) {
		t.Fatal("two-hop tunnel did not reach origin")
	}
	for deadline := time.Now().Add(time.Second); transitBytes.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if transitBytes.Load() == 0 {
		t.Fatal("successful request bypassed exit relay")
	}
	t.Log("TWO_HOP_AND_ORDINARY_PASS")
	stopExit()
	if probe(cascade) {
		t.Fatal("cascade fell back to direct when exit stopped")
	}
	if !probe(direct) {
		t.Fatal("ordinary profile affected by exit failure")
	}
	t.Log("EXIT_DOWN_NO_FALLBACK_PASS")
	exit.XrayCascades = nil
	stopExit = start(compile("exit-revoked", exit), exitPort)
	if probe(cascade) {
		t.Fatal("revoked transit identity still connects")
	}
	if !probe(direct) {
		t.Fatal("ordinary profile affected by transit revocation")
	}
	t.Log("TRANSIT_REVOKE_PASS")
	stopExit()
	exit.XrayCascades = &model.XrayCascadesSpec{Version: 1, Exits: []model.XrayCascadeExit{{ID: cascadeID, ServiceID: cascadeServiceID, ClientID: cascadeTransitID}}}
	start(compile("exit-restored", exit), exitPort)
	restored := false
	for attempt := 0; attempt < 6; attempt++ {
		if probe(cascade) {
			restored = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !restored {
		t.Fatal("restored transit cannot connect after bounded reconnection window")
	}
	stopEntry()
	entry.XrayCascades.Entries[0].Clients = nil
	start(compile("entry-revoked", entry), entry.Services[0].Port)
	if probe(cascade) {
		t.Fatal("revoked cascade client still connects")
	}
	if !probe(direct) {
		t.Fatal("ordinary authorization changed by cascade revocation")
	}
	t.Log("CASCADE_CLIENT_REVOKE_AND_ORDINARY_PRESERVED_PASS")
}
