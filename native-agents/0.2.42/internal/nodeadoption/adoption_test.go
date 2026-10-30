package nodeadoption

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

const identity = "11111111-1111-4111-8111-111111111111"
const tlsIdentity = "22222222-2222-4222-8222-222222222222"

type fixtureData struct {
	plan            InspectionPlan
	raw, chain, key []byte
	roots           *x509.CertPool
	now             time.Time
	private         string
}

func write(t *testing.T, name string, data []byte) {
	t.Helper()
	if os.MkdirAll(filepath.Dir(name), 0700) != nil || os.WriteFile(name, data, 0600) != nil {
		t.Fatal("fixture write")
	}
}
func fixture(t *testing.T) fixtureData {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal("fixture CA")
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal("fixture CA certificate")
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"node.example.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal("fixture leaf")
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	root := t.TempDir()
	write(t, root+"/archive/fullchain.pem", chain)
	write(t, root+"/archive/privkey.pem", keyPEM)
	if os.Mkdir(root+"/live", 0700) != nil || os.Symlink("../archive/fullchain.pem", root+"/live/fullchain.pem") != nil || os.Symlink("../archive/privkey.pem", root+"/live/privkey.pem") != nil {
		t.Fatal("fixture links")
	}
	private := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	cfg := map[string]any{"inbounds": []any{
		map[string]any{"tag": "reality", "listen": "0.0.0.0", "port": 443, "protocol": "vless", "settings": map[string]any{"clients": []any{}, "decryption": "none"}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": "/dev/shm/nginx.sock", "serverNames": []string{"node.example.test"}, "shortIds": []string{""}, "privateKey": private, "show": false, "xver": 1}}},
		map[string]any{"tag": "hysteria", "listen": "0.0.0.0", "port": 443, "protocol": "hysteria", "settings": map[string]any{"clients": []any{}, "version": 2}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificateFile": "/cert/live/fullchain.pem", "keyFile": "/cert/live/privkey.pem"}}}}},
	}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}, map[string]any{"tag": "WARP", "protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]any{"interface": "warp"}}}}, "routing": map[string]any{"rules": []any{map[string]any{"domain": []string{"domain:example.test"}, "outboundTag": "WARP"}}}}
	raw := encoded(cfg)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	plan := InspectionPlan{Version: 1, TenantID: identity, ImportID: identity, NodeID: identity, SourceNodeID: identity, ReviewedSHA256: strings.Repeat("a", 64), SourceConfigSHA256: digest(raw), ExpectedHostname: "fixture", Mounts: []Mount{{ContainerPath: "/cert", HostPath: root}}, TLSDomains: []Domain{{InboundTag: "hysteria", Domain: "node.example.test"}}}
	return fixtureData{plan, raw, chain, keyPEM, roots, now, private}
}
func (f fixtureData) inspect() (*Inspection, error) {
	return inspect(f.plan, f.raw, "fixture", f.roots, f.now)
}
func (f fixtureData) stagePlan(t *testing.T) StagePlan {
	t.Helper()
	inspection, e := f.inspect()
	if e != nil {
		t.Fatal("fixture inspection")
	}
	services := []xrayprofile.SourceService{
		{InboundID: identity, InboundTag: "reality", Enabled: true, Service: model.ServiceSpec{ID: identity, Protocol: "vless", Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "reality", Reality: &model.RealitySpec{Destination: "/dev/shm/nginx.sock", ServerName: "node.example.test", SecretRef: "reality/" + identity}}},
		{InboundID: tlsIdentity, InboundTag: "hysteria", Enabled: false, Service: model.ServiceSpec{ID: tlsIdentity, Protocol: "hysteria2", Listen: "0.0.0.0", Port: 443, Transport: "udp", Security: "tls", TLS: &model.TLSSpec{CertificateID: tlsIdentity, ServerName: "node.example.test"}}},
	}
	profile, _, e := xrayprofile.Project(f.raw, []model.XrayProfileBinding{{ServiceID: identity, InboundTag: "reality"}, {ServiceID: tlsIdentity, InboundTag: "hysteria"}})
	if e != nil {
		t.Fatal("fixture profile")
	}
	var c Certificate
	for _, m := range inspection.Receipt.Materials {
		if m.Security == "tls" {
			c = Certificate{AdoptionSHA256: inspection.MaterialSHA256, CertificateID: tlsIdentity, NodeID: identity, InventorySHA256: f.plan.ReviewedSHA256, ReviewedSHA256: f.plan.ReviewedSHA256, Domain: m.Domain, FingerprintSHA256: m.FingerprintSHA256, ChainSHA256: m.ChainSHA256, NotAfter: *m.NotAfter, State: "prepared"}
		}
	}
	return StagePlan{Inspection: f.plan, InspectionSHA256: inspection.SHA256, Preparation: Preparation{NodeID: identity, ImportID: identity, InventorySHA256: f.plan.ReviewedSHA256, ReviewedSHA256: f.plan.ReviewedSHA256, ProfileSHA256: profile.SHA256, Services: services, State: "prepared"}, Certificates: []Certificate{c}}
}
func TestInspectSourcePreservedAndSecretsExcluded(t *testing.T) {
	f := fixture(t)
	before, _ := os.Stat(f.plan.Mounts[0].HostPath + "/archive/privkey.pem")
	i, e := f.inspect()
	if e != nil {
		t.Fatal("valid inspection rejected")
	}
	again, e := f.inspect()
	if e != nil || again.SHA256 != i.SHA256 {
		t.Fatal("unstable inspection identity")
	}
	if i.Receipt.CutoverReady || i.Receipt.RuntimeInstalled || i.Receipt.SourceStopped || i.Receipt.PhysicalProof != "owner_local_files" {
		t.Fatal("overstated proof")
	}
	if strings.Join(i.Receipt.Dependencies.UnixSockets, ",") != "/dev/shm/nginx.sock" || strings.Join(i.Receipt.Dependencies.Interfaces, ",") != "warp" {
		t.Fatal("dependency loss")
	}
	b := i.PublicBundle()
	wire := encoded(i)
	for _, data := range b.Files {
		wire = append(wire, data...)
	}
	if bytes.Contains(wire, []byte(f.private)) || bytes.Contains(wire, f.key) || bytes.Contains(wire, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("private data in public inspection")
	}
	key, _ := os.ReadFile(f.plan.Mounts[0].HostPath + "/archive/privkey.pem")
	after, _ := os.Stat(f.plan.Mounts[0].HostPath + "/archive/privkey.pem")
	if !bytes.Equal(key, f.key) || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		t.Fatal("source changed")
	}
}
func TestTLSRejectsInvalidMaterial(t *testing.T) {
	f := fixture(t)
	other := fixture(t)
	tests := []struct {
		name, domain string
		chain, key   []byte
		roots        *x509.CertPool
		now          time.Time
	}{
		{"wrong-key", "node.example.test", f.chain, other.key, f.roots, f.now},
		{"wrong-name", "other.example.test", f.chain, f.key, f.roots, f.now},
		{"expired", "node.example.test", f.chain, f.key, f.roots, f.now.Add(48 * time.Hour)},
		{"untrusted", "node.example.test", f.chain, f.key, other.roots, f.now},
		{"private-in-chain", "node.example.test", append(append([]byte{}, f.chain...), f.key...), f.key, f.roots, f.now},
		{"chain-garbage", "node.example.test", append(append([]byte{}, f.chain...), []byte("garbage")...), f.key, f.roots, f.now},
		{"key-garbage", "node.example.test", f.chain, append(append([]byte{}, f.key...), []byte("garbage")...), f.roots, f.now},
		{"second-key", "node.example.test", f.chain, append(append([]byte{}, f.key...), f.key...), f.roots, f.now},
		{"malformed-certificate-prefix", "node.example.test", append([]byte("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"), f.chain...), f.key, f.roots, f.now},
		{"malformed-key-prefix", "node.example.test", f.chain, append([]byte("-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n"), f.key...), f.roots, f.now},
	}
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			if _, _, e := verifyPair(v.domain, v.chain, v.key, v.roots, v.now); e == nil {
				t.Fatal("invalid TLS accepted")
			}
		})
	}
}
func TestMountBoundariesAndFileTypes(t *testing.T) {
	for _, name := range []string{"escape", "writable-key", "writable-directory", "writable-target-directory", "oversize", "fifo", "mount-link", "duplicate-mount", "traversal", "wrong-host", "wrong-config", "extra-domain"} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			root := f.plan.Mounts[0].HostPath
			switch name {
			case "escape":
				os.Remove(root + "/live/privkey.pem")
				outside := t.TempDir() + "/key"
				write(t, outside, f.key)
				os.Symlink(outside, root+"/live/privkey.pem")
			case "writable-key":
				os.Chmod(root+"/archive/privkey.pem", 0666)
			case "writable-directory":
				os.Chmod(root+"/live", 0777)
			case "writable-target-directory":
				os.Chmod(root+"/archive", 0777)
			case "oversize":
				write(t, root+"/archive/privkey.pem", bytes.Repeat([]byte("x"), 65537))
			case "fifo":
				os.Remove(root + "/archive/privkey.pem")
				if e := makeFIFO(root + "/archive/privkey.pem"); e != nil {
					t.Fatal("fixture FIFO")
				}
			case "mount-link":
				alias := t.TempDir() + "/alias"
				os.Symlink(root, alias)
				f.plan.Mounts[0].HostPath = alias
			case "duplicate-mount":
				f.plan.Mounts = append(f.plan.Mounts, f.plan.Mounts[0])
			case "traversal":
				f.raw = bytes.ReplaceAll(f.raw, []byte("/cert/live/privkey.pem"), []byte("/cert/live/../archive/privkey.pem"))
				f.plan.SourceConfigSHA256 = digest(f.raw)
			case "wrong-host":
				f.plan.ExpectedHostname = "other"
			case "wrong-config":
				f.plan.SourceConfigSHA256 = strings.Repeat("0", 64)
			case "extra-domain":
				f.plan.TLSDomains = append(f.plan.TLSDomains, Domain{"missing", "node.example.test"})
			}
			if _, e := f.inspect(); e == nil {
				t.Fatal("unsafe material accepted")
			}
		})
	}
	f := fixture(t)
	nested := t.TempDir()
	write(t, nested+"/fullchain.pem", f.chain)
	write(t, nested+"/privkey.pem", f.key)
	f.plan.Mounts = append(f.plan.Mounts, Mount{"/cert/live", nested})
	if _, e := f.inspect(); e != nil {
		t.Fatal("longest mount mapping rejected")
	}
}
func TestStageAgentLayoutAndRetry(t *testing.T) {
	f := fixture(t)
	plan := f.stagePlan(t)
	b, e := stage(plan, f.raw, "fixture", f.roots, f.now)
	if e != nil {
		t.Fatal("valid stage rejected")
	}
	out := t.TempDir() + "/bundle"
	s, e := Publish(out, b)
	if e != nil || s.Existing || s.CutoverReady {
		t.Fatal("publish")
	}
	s2, e := Publish(out, b)
	if e != nil || !s2.Existing || s.ManifestSHA256 != s2.ManifestSHA256 {
		t.Fatal("read-only exact retry")
	}
	actual, e := os.ReadFile(out + "/node-data/secrets/reality/" + identity + ".key")
	if e != nil || strings.TrimSpace(string(actual)) != f.private {
		t.Fatal("REALITY material differs")
	}
	base := out + "/node-data/certificates/" + tlsIdentity + "/current"
	if _, e = tls.LoadX509KeyPair(base+"/fullchain.pem", base+"/private.key"); e != nil {
		t.Fatal("agent certificate layout unusable")
	}
	var receipt StageReceipt
	raw, _ := os.ReadFile(out + "/stage.json")
	if json.Unmarshal(raw, &receipt) != nil || receipt.Services[1].Enabled || receipt.CutoverReady || receipt.SourceStopped || receipt.RuntimeInstalled {
		t.Fatal("disabled source listener or held state lost")
	}
	write(t, out+"/extra", []byte("conflict"))
	if _, e = Publish(out, b); e == nil {
		t.Fatal("unexpected file accepted")
	}
}
func TestStageRejectsBindingDrift(t *testing.T) {
	for _, name := range []string{"inspection", "node", "review", "profile", "active", "clients", "cert-key", "cert-node", "cert-expiry", "extra-cert", "domain", "duplicate-inbound", "service-port"} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			p := f.stagePlan(t)
			switch name {
			case "inspection":
				p.InspectionSHA256 = strings.Repeat("0", 64)
			case "node":
				p.Preparation.NodeID = tlsIdentity
			case "review":
				p.Preparation.ReviewedSHA256 = strings.Repeat("0", 64)
			case "profile":
				p.Preparation.ProfileSHA256 = strings.Repeat("0", 64)
			case "active":
				p.Preparation.State = "active"
			case "clients":
				p.Preparation.Services[0].Service.Clients = []model.ClientSpec{{ID: identity, StatsKey: tlsIdentity}}
			case "cert-key":
				p.Certificates[0].FingerprintSHA256 = strings.Repeat("0", 64)
			case "cert-node":
				p.Certificates[0].NodeID = tlsIdentity
			case "cert-expiry":
				p.Certificates[0].NotAfter = p.Certificates[0].NotAfter.Add(time.Second)
			case "extra-cert":
				c := p.Certificates[0]
				c.CertificateID = identity
				p.Certificates = append(p.Certificates, c)
			case "domain":
				p.Preparation.Services[1].Service.TLS.ServerName = "other.example.test"
			case "duplicate-inbound":
				p.Preparation.Services[1].InboundID = identity
			case "service-port":
				p.Preparation.Services[0].Service.Port++
			}
			if _, e := stage(p, f.raw, "fixture", f.roots, f.now); e == nil {
				t.Fatal("mismatched preparation accepted")
			}
		})
	}
}
func TestStrictPlanJSON(t *testing.T) {
	f := fixture(t)
	p := f.stagePlan(t)
	valid := encoded(p)
	var out StagePlan
	if DecodePlan(valid, &out) != nil {
		t.Fatal("valid JSON rejected")
	}
	for _, raw := range [][]byte{
		[]byte(`{"inspection":{"version":1,"version":2}}`), []byte(`{"inspection":{"Version":1}}`),
		[]byte(`{"inspection":{"mounts":[{"host_path":"a","host_path":"b"}]}}`),
		bytes.Replace(valid, []byte(`"source_enabled":true`), []byte(`"source_enabled":true,"unexpected":false`), 1),
		append(append([]byte{}, valid...), []byte(` {}`)...), []byte(`null`),
	} {
		if DecodePlan(raw, &out) == nil {
			t.Fatal("ambiguous plan accepted")
		}
	}
}
func TestPublishConcurrentAndRefusesChangedPermissions(t *testing.T) {
	f := fixture(t)
	i, e := f.inspect()
	if e != nil {
		t.Fatal("inspection")
	}
	b := i.PublicBundle()
	parent := t.TempDir()
	out := parent + "/bundle"
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for k := 0; k < 6; k++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := Publish(out, b); errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal("concurrent publication failed")
		}
	}
	leftovers, _ := filepath.Glob(parent + "/.node-material-*")
	if len(leftovers) != 0 {
		t.Fatal("private staging directory leaked")
	}
	os.Chmod(out+"/inspection.json", 0644)
	if _, e := Publish(out, b); e == nil {
		t.Fatal("permissions drift accepted")
	}
	empty := parent + "/empty"
	os.Mkdir(empty, 0700)
	if _, e := Publish(empty, b); e == nil {
		t.Fatal("existing empty directory replaced")
	}
	os.Symlink(out, parent+"/alias")
	if _, e := Publish(parent+"/alias", b); e == nil {
		t.Fatal("symlink destination accepted")
	}
	b.Files["../escape"] = []byte("bad")
	if _, e := Publish(parent+"/new", b); e == nil {
		t.Fatal("escaping path accepted")
	}
}

func TestPublishRejectsHardlinkedOutput(t *testing.T) {
	f := fixture(t)
	i, e := f.inspect()
	if e != nil {
		t.Fatal("inspection")
	}
	parent := t.TempDir()
	out := parent + "/bundle"
	b := i.PublicBundle()
	if _, e = Publish(out, b); e != nil {
		t.Fatal("publication")
	}
	if os.Link(out+"/inspection.json", parent+"/external-link") != nil {
		t.Fatal("fixture hardlink")
	}
	if _, e = Publish(out, b); e == nil {
		t.Fatal("hardlinked private output accepted")
	}
}
