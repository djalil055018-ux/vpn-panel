package compiler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"testing"
	"time"

	"vpn-platform/internal/model"
)

// Opt-in real core check. Every listener and all traffic stay on loopback.
func TestVLESSTransportNativeTunnelAndRevoke(t *testing.T) {
	for _, transport := range []string{"ws", "grpc"} {
		t.Run(transport, func(t *testing.T) { runVLESSTransportNative(t, transport) })
	}
}
func runVLESSTransportNative(t *testing.T, transportName string) {
	binary := os.Getenv("VPN_TEST_XRAY_BINARY")
	if binary == "" {
		t.Skip("set VPN_TEST_XRAY_BINARY for isolated real-core test")
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
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
	serverPort, proxyPort := port(), port()
	clientID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	service := model.ServiceSpec{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Protocol: "vless", Listen: "127.0.0.1", Port: serverPort, Transport: transportName, Security: "tls", TLS: &model.TLSSpec{ServerName: "localhost", CertificateFile: certPath, KeyFile: keyPath}, Clients: []model.ClientSpec{{ID: clientID}}}
	serverPath, clientPath := filepath.Join(dir, "server.json"), filepath.Join(dir, "client.json")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("origin received request")
		io.WriteString(w, "vless-native-ok")
	}))
	defer origin.Close()
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
		// Only the isolated test origin is allowed; production compiler policy stays intact.
		cfg["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1"}, "port": origin.Listener.Addr().(*net.TCPAddr).Port}}}
		data, e = json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		write(serverPath, data)
	}
	compile()
	clientCfg := map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": proxyPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "users": []any{map[string]any{"id": clientID, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "disableSystemRoot": true, "certificates": []any{map[string]any{"certificateFile": certPath, "usage": "verify"}}}}}}}
	stream := clientCfg["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	stream["network"] = transportName
	if transportName == "ws" {
		path, _ := model.XHTTPPath(service.ID)
		stream["wsSettings"] = map[string]any{"path": path}
	} else {
		name, _ := model.GRPCServiceName(service.ID)
		stream["grpcSettings"] = map[string]any{"serviceName": name}
	}
	data, err := json.Marshal(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	write(clientPath, data)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	stopServer := start(serverPath, serverPort)
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
		return res.StatusCode == 200 && string(b) == "vless-native-ok"
	}
	if !probe() {
		t.Fatal("VLESS TLS tunnel did not reach loopback origin")
	}
	stopServer()
	service.Clients = nil
	compile()
	stopRevoked := start(serverPath, serverPort)
	if probe() {
		t.Fatal("revoked VLESS credential still opens a new tunnel")
	}
	stopRevoked()
	service.Clients = []model.ClientSpec{{ID: clientID}}
	compile()
	start(serverPath, serverPort)
	if !probe() {
		t.Fatal("restored VLESS credential cannot connect")
	}
}
