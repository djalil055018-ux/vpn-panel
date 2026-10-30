package compiler

import (
	"context"

	"encoding/base64"
	"encoding/json"

	"fmt"
	"io"

	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func TestWireGuardNativeTunnelAndRevoke(t *testing.T) {
	binary := os.Getenv("VPN_TEST_XRAY_BINARY")
	if binary == "" {
		t.Skip("set VPN_TEST_XRAY_BINARY for isolated real-core test")
	}
	originIP := os.Getenv("VPN_TEST_WG_ORIGIN_IP")
	if net.ParseIP(originIP) == nil || !net.ParseIP(originIP).IsPrivate() || net.ParseIP(originIP).IsLoopback() {
		t.Skip("isolated namespace private origin IP required")
	}
	dir := t.TempDir()
	t.Cleanup(func() {
		if t.Failed() {
			paths, _ := filepath.Glob(filepath.Join(dir, "core-*.log"))
			for _, path := range paths {
				data, _ := os.ReadFile(path)
				t.Logf("test core log: %s", data)
			}
		}
	})
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	port := func() int {
		t.Helper()
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return p
	}
	serverPort, proxyPort, readinessPort := port(), port(), port()
	serverKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	clientKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	serverPublic, _ := model.WireGuardPublicKey(serverKey)
	clientPublic, _ := model.WireGuardPublicKey(clientKey)
	psk := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	service := model.ServiceSpec{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Protocol: "wireguard", Listen: "127.0.0.1", Port: serverPort, Transport: "udp", Security: "wireguard", WireGuard: &model.WireGuardSpec{PrivateKey: serverKey}, Clients: []model.ClientSpec{{ID: "client", StatsKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", WireGuard: &model.WireGuardPeer{PublicKey: clientPublic, PresharedKey: psk, Address: "10.66.0.2/32"}}}}
	serverPath, clientPath := filepath.Join(dir, "server.json"), filepath.Join(dir, "client.json")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("origin received request")
		io.WriteString(w, "wireguard-native-ok")
	}))
	listener, e := net.Listen("tcp", net.JoinHostPort(originIP, "0"))
	if e != nil {
		t.Fatal(e)
	}
	origin.Listener = listener
	origin.Start()
	defer origin.Close()
	udpOrigin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(originIP)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpOrigin.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := udpOrigin.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = udpOrigin.WriteToUDP(b[:n], a)
		}
	}()
	compile := func() {
		t.Helper()
		data, e := CompileXray(model.DesiredState{Services: []model.ServiceSpec{service}})
		if e != nil {
			t.Fatal(e)
		}
		var cfg map[string]any
		if e = json.Unmarshal(data, &cfg); e != nil {
			t.Fatal(e)
		}
		delete(cfg, "api")
		cfg["inbounds"] = append(cfg["inbounds"].([]any), map[string]any{"listen": "127.0.0.1", "port": readinessPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}})
		// Only the isolated test origin is allowed; production compiler policy stays intact.
		cfg["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{originIP}, "port": origin.Listener.Addr().(*net.TCPAddr).Port}, map[string]any{"action": "allow", "network": "udp", "ip": []string{originIP}, "port": udpOrigin.LocalAddr().(*net.UDPAddr).Port}}}
		data, e = json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		write(serverPath, data)
	}
	compile()
	clientCfg := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": proxyPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}}}, "outbounds": []any{map[string]any{"protocol": "wireguard", "settings": map[string]any{"noKernelTun": true, "secretKey": clientKey, "address": []string{"10.66.0.2/32"}, "peers": []any{map[string]any{"publicKey": serverPublic, "preSharedKey": psk, "endpoint": fmt.Sprintf("127.0.0.1:%d", serverPort), "allowedIPs": []string{"0.0.0.0/0"}}}}}}}
	data, err := json.Marshal(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	write(clientPath, data)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := func(path string, p int) func() {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, "run", "-config", path)
		log, e := os.CreateTemp(dir, "core-*.log")
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				_ = log.Close()
			}
		}
		t.Cleanup(stop)
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 100*time.Millisecond)
			if e == nil {
				c.Close()
				return stop
			}
			time.Sleep(25 * time.Millisecond)
		}
		stop()
		b, _ := os.ReadFile(log.Name())
		t.Fatalf("core failed to listen: %s", b)
		return stop
	}
	stopServer := start(serverPath, readinessPort)
	start(clientPath, proxyPort)
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	probe := func() bool {
		res, e := client.Get(origin.URL)
		if e != nil {
			t.Logf("probe: %v", e)
			return false
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode == 200 && string(b) == "wireguard-native-ok"
	}
	if !probe() || !shadowsocksUDPProbeTo(proxyPort, udpOrigin.LocalAddr().(*net.UDPAddr).Port, net.ParseIP(originIP)) {
		t.Fatal("WireGuard tunnel did not reach loopback origin")
	}
	stopServer()
	service.Clients = nil
	compile()
	stopRevoked := start(serverPath, readinessPort)
	if probe() || shadowsocksUDPProbeTo(proxyPort, udpOrigin.LocalAddr().(*net.UDPAddr).Port, net.ParseIP(originIP)) {
		t.Fatal("revoked WireGuard credential still opens a new tunnel")
	}
	stopRevoked()
	service.Clients = []model.ClientSpec{{ID: "client", WireGuard: &model.WireGuardPeer{PublicKey: clientPublic, PresharedKey: psk, Address: "10.66.0.2/32"}}}
	compile()
	start(serverPath, readinessPort)
	if !probe() || !shadowsocksUDPProbeTo(proxyPort, udpOrigin.LocalAddr().(*net.UDPAddr).Port, net.ParseIP(originIP)) {
		t.Fatal("restored WireGuard credential cannot connect")
	}
}
