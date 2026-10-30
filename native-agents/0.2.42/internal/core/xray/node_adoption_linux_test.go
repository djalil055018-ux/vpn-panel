package xray

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/nodeadoption"
	"vpn-platform/internal/xrayprofile"
)

// The child gets an isolated synthetic trust store. No global test process or
// host trust configuration is changed, and no daemon is launched by this test.
func TestNodeMaterialAdoptionHelper(t *testing.T) {
	if os.Getenv("VPN_MATERIAL_HELPER") != "1" {
		return
	}
	root := os.Getenv("VPN_MATERIAL_FIXTURE")
	fail := func() { os.Exit(2) }
	raw, e := os.ReadFile(filepath.Join(root, "source.json"))
	if e != nil {
		fail()
	}
	planRaw, e := os.ReadFile(filepath.Join(root, "stage-plan.json"))
	if e != nil {
		fail()
	}
	var p nodeadoption.StagePlan
	if nodeadoption.DecodePlan(planRaw, &p) != nil {
		fail()
	}
	i, e := nodeadoption.Inspect(p.Inspection, raw)
	if e != nil {
		fail()
	}
	p.InspectionSHA256 = i.SHA256
	for _, m := range i.Receipt.Materials {
		if m.Security == "tls" {
			p.Certificates = []nodeadoption.Certificate{{AdoptionSHA256: i.MaterialSHA256, CertificateID: tlsTestID, NodeID: tlsTestID, InventorySHA256: p.Inspection.ReviewedSHA256, ReviewedSHA256: p.Inspection.ReviewedSHA256, Domain: m.Domain, FingerprintSHA256: m.FingerprintSHA256, ChainSHA256: m.ChainSHA256, NotAfter: *m.NotAfter, State: "prepared"}}
		}
	}
	b, e := nodeadoption.Stage(p, raw)
	if e != nil {
		fail()
	}
	if _, e = nodeadoption.Publish(filepath.Join(root, "bundle"), b); e != nil {
		fail()
	}
	os.Exit(0)
}

func TestNodeMaterialBundleConsumedByActualAgent(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source-certificates")
	writeTLSFixture(t, source, "test.example", time.Now().Add(time.Hour))
	private := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{21}, 32))
	realityID := "22222222-2222-4222-8222-222222222222"
	cfg := map[string]any{"inbounds": []any{
		map[string]any{"tag": "reality", "listen": "0.0.0.0", "port": 443, "protocol": "vless", "settings": map[string]any{"clients": []any{}, "decryption": "none"}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"dest": "test.example:443", "serverNames": []string{"test.example"}, "shortIds": []string{""}, "privateKey": private}}},
		map[string]any{"tag": "hysteria", "listen": "0.0.0.0", "port": 443, "protocol": "hysteria", "settings": map[string]any{"clients": []any{}, "version": 2}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificateFile": "/source/fullchain.pem", "keyFile": "/source/private.key"}}}}},
	}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}, "routing": map[string]any{"rules": []any{}}}
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	host, _ := os.Hostname()
	bindings := []model.XrayProfileBinding{{ServiceID: realityID, InboundTag: "reality"}, {ServiceID: tlsTestID, InboundTag: "hysteria"}}
	profile, _, e := xrayprofile.Project(raw, bindings)
	if e != nil {
		t.Fatal("fixture profile")
	}
	services := []xrayprofile.SourceService{
		{InboundID: realityID, InboundTag: "reality", Enabled: true, Service: model.ServiceSpec{ID: realityID, Protocol: "vless", Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "reality", Reality: &model.RealitySpec{Destination: "test.example:443", ServerName: "test.example", SecretRef: "reality/" + realityID}}},
		{InboundID: tlsTestID, InboundTag: "hysteria", Enabled: true, Service: model.ServiceSpec{ID: tlsTestID, Protocol: "hysteria2", Listen: "0.0.0.0", Port: 443, Transport: "udp", Security: "tls", TLS: &model.TLSSpec{CertificateID: tlsTestID, ServerName: "test.example"}}},
	}
	plan := nodeadoption.StagePlan{Inspection: nodeadoption.InspectionPlan{Version: 1, TenantID: tlsTestID, ImportID: tlsTestID, NodeID: tlsTestID, SourceNodeID: tlsTestID, ReviewedSHA256: sha, SourceConfigSHA256: sha, ExpectedHostname: host, Mounts: []nodeadoption.Mount{{ContainerPath: "/source", HostPath: source}}, TLSDomains: []nodeadoption.Domain{{InboundTag: "hysteria", Domain: "test.example"}}}, Preparation: nodeadoption.Preparation{NodeID: tlsTestID, ImportID: tlsTestID, InventorySHA256: sha, ReviewedSHA256: sha, ProfileSHA256: profile.SHA256, Services: services, State: "prepared"}}
	planRaw, _ := json.Marshal(plan)
	if os.WriteFile(filepath.Join(root, "source.json"), raw, 0600) != nil || os.WriteFile(filepath.Join(root, "stage-plan.json"), planRaw, 0600) != nil {
		t.Fatal("fixture write")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNodeMaterialAdoptionHelper$")
	cmd.Env = append(os.Environ(), "VPN_MATERIAL_HELPER=1", "VPN_MATERIAL_FIXTURE="+root, "SSL_CERT_FILE="+filepath.Join(source, "fullchain.pem"), "SSL_CERT_DIR="+filepath.Join(root, "empty-trust"))
	if cmd.Run() != nil {
		t.Fatal("public adoption API stage failed")
	}
	d := New(filepath.Join(root, "bundle", "node-data"))
	state := model.DesiredState{XrayProfile: profile, Services: []model.ServiceSpec{services[0].Service, services[1].Service}}
	resolved, materials, e := d.resolveRealitySecrets(state)
	if e != nil || len(materials) != 1 || resolved.Services[0].Reality.PrivateKey != private || materials[0].PublicKey != profile.Bindings[0].RealityPublicKey {
		t.Fatal("agent cannot resolve original REALITY material")
	}
	resolved, e = d.resolveTLSCertificates(resolved)
	if e != nil {
		t.Fatal("agent cannot resolve staged TLS material")
	}
	if _, e = xrayprofile.Compile(profile, resolved.Services); e != nil {
		t.Fatal("agent-resolved profile cannot compile")
	}
	if os.Geteuid() == 0 {
		runtime, e := d.publishTLSRuntime(*resolved.Services[1].TLS, os.Getgid())
		if e != nil {
			t.Fatal("agent runtime certificate copy")
		}
		info, e := os.Stat(runtime.KeyFile)
		if e != nil || info.Mode().Perm() != 0640 {
			t.Fatal("runtime key permissions")
		}
	}
	info, e := os.Stat(resolved.Services[1].TLS.KeyFile)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("original private key permissions changed")
	}
	// Imported keys are never replaced with freshly generated keys on failure.
	if os.Remove(filepath.Join(d.BaseDir, "secrets", "reality", realityID+".key")) != nil {
		t.Fatal("fixture key removal")
	}
	if _, _, e = d.resolveRealitySecrets(state); e == nil {
		t.Fatal("missing imported key regenerated")
	}
}
