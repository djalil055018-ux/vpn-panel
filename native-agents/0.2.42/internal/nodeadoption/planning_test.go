package nodeadoption

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

func planningFixture(t *testing.T) (fixtureData, PlanningRequest, []byte, string) {
	t.Helper()
	f := fixture(t)
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	if e != nil {
		t.Fatal("fixture inventory")
	}
	var inv, cfg map[string]any
	if json.Unmarshal(raw, &inv) != nil || json.Unmarshal(f.raw, &cfg) != nil {
		t.Fatal("fixture JSON")
	}
	// The shared fixture uses the same all-ones UUID as our synthetic native
	// node. Give the subscriber a distinct credential so leak detection cannot
	// mistake a legitimate service identity for an exported subscriber secret.
	sensitive := "99999999-aaaa-4999-8999-999999999999"
	inv["users"].([]any)[0].(map[string]any)["vlessUuid"] = sensitive
	profile := "44444444-4444-4444-8444-444444444444"
	metadata := []any{}
	for idx, v := range cfg["inbounds"].([]any) {
		in := v.(map[string]any)
		s := in["streamSettings"].(map[string]any)
		id := identity
		if idx == 1 {
			id = tlsIdentity
		}
		metadata = append(metadata, map[string]any{"uuid": id, "profileUuid": profile, "tag": in["tag"], "type": in["protocol"], "network": s["network"], "security": s["security"], "port": in["port"], "rawInbound": in})
	}
	inv["nodes"] = []any{map[string]any{"uuid": identity, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": profile, "activeInbounds": metadata[:1]}}}
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": profile, "config": cfg, "inbounds": metadata, "nodes": []any{map[string]any{"uuid": identity}}}}}
	inventory := encoded(inv)
	f.plan.ReviewedSHA256 = digest(inventory)
	request := PlanningRequest{Version: 1, TenantID: f.plan.TenantID, ImportID: f.plan.ImportID, NodeID: f.plan.NodeID, SourceNodeID: f.plan.SourceNodeID, ReviewedSHA256: f.plan.ReviewedSHA256, ExpectedHostname: f.plan.ExpectedHostname, Mounts: f.plan.Mounts, TLSDomains: f.plan.TLSDomains}
	return f, request, inventory, sensitive
}
func plannedPreparation(f fixtureData, t *testing.T) StagePlan {
	p := f.stagePlan(t)
	p.Preparation.Services[0].Service.Reality.Fingerprint = "chrome"
	return p
}
func TestReviewedPlanningChain(t *testing.T) {
	f, req, inventory, sensitive := planningFixture(t)
	first, e := PlanInspection(req, inventory)
	if e != nil {
		t.Fatal("inspection plan")
	}
	var plan InspectionPlan
	if DecodePlan(first.Files["inspection-plan.json"], &plan) != nil {
		t.Fatal("inspection plan decode")
	}
	if plan.SourceConfigSHA256 != digest(first.Files["source-config.json"]) || !bytes.Equal(first.Files["source-config.json"], f.raw) {
		t.Fatal("source template differs")
	}
	for name, data := range first.Files {
		if bytes.Contains(data, []byte(sensitive)) {
			t.Fatal("subscriber credential exported")
		}
		if name != "source-config.json" && bytes.Contains(data, []byte(f.private)) {
			t.Fatal("node private key in public plan")
		}
	}
	if _, e = Publish(t.TempDir()+"/plan", first); e != nil {
		t.Fatal("planning bundle publication")
	}
	i, e := f.inspect()
	if e != nil {
		t.Fatal("inspection")
	}
	public := i.PublicBundle()
	requests := 0
	for name, data := range public.Files {
		if strings.HasPrefix(name, "prepare-tls/") {
			requests++
			var request TLSPreparationRequest
			if DecodePlan(data, &request) != nil || request.AdoptionSHA256 != i.MaterialSHA256 || request.AdoptionSHA256 == i.SHA256 || request.NodeID != req.NodeID || request.SourceNodeID != req.SourceNodeID || request.FullchainPEM != string(f.chain) {
				t.Fatal("TLS API request mismatch")
			}
		}
	}
	if requests != 1 {
		t.Fatal("TLS API request count")
	}
	// Use only the public receipt after transfer to CP.
	var publicInspection Inspection
	if DecodePlan(public.Files["inspection.json"], &publicInspection) != nil {
		t.Fatal("public receipt decode")
	}
	p := plannedPreparation(f, t)
	second, e := PlanPreparation(req, inventory, publicInspection, p.Certificates)
	if e != nil {
		t.Fatal("native TLS assignments")
	}
	var apiRequest XrayPreparationRequest
	if DecodePlan(second.Files["prepare-xray-node.json"], &apiRequest) != nil || len(apiRequest.TLSAssignments) != 1 || apiRequest.TLSAssignments[0].SourceInboundID != tlsIdentity || apiRequest.TLSAssignments[0].CertificateID != tlsIdentity {
		t.Fatal("TLS inbound ID assignment")
	}
	third, e := PlanStage(req, inventory, publicInspection, p.Preparation, p.Certificates)
	if e != nil {
		t.Fatal("stage planning")
	}
	var stagePlan StagePlan
	if DecodePlan(third.Files["stage-plan.json"], &stagePlan) != nil {
		t.Fatal("stage plan decode")
	}
	if stagePlan.Preparation.Services[1].Enabled {
		t.Fatal("disabled source enabled")
	}
	b, e := stage(stagePlan, third.Files["source-config.json"], "fixture", f.roots, f.now)
	if e != nil {
		t.Fatal("planned stage rejected on original node")
	}
	if _, e = Publish(t.TempDir()+"/stage", b); e != nil {
		t.Fatal("planned stage publication")
	}
}
func TestUserOnlyReviewKeepsMaterialIdentity(t *testing.T) {
	f, req, inventory, _ := planningFixture(t)
	old, e := f.inspect()
	if e != nil {
		t.Fatal("inspection")
	}
	p := plannedPreparation(f, t)
	var next map[string]any
	if json.Unmarshal(inventory, &next) != nil {
		t.Fatal("fixture")
	}
	user := next["users"].([]any)[0].(map[string]any)
	traffic := user["userTraffic"].(map[string]any)
	traffic["lifetimeUsedTrafficBytes"] = traffic["lifetimeUsedTrafficBytes"].(float64) + 1
	inventory = encoded(next)
	req.ReviewedSHA256 = digest(inventory)
	f.plan.ReviewedSHA256 = req.ReviewedSHA256
	fresh, e := f.inspect()
	if e != nil || fresh.SHA256 == old.SHA256 || fresh.MaterialSHA256 != old.MaterialSHA256 {
		t.Fatal("unrelated user delta invalidated physical material")
	}
	p.Preparation.ReviewedSHA256 = req.ReviewedSHA256
	for n := range p.Certificates {
		p.Certificates[n].ReviewedSHA256 = req.ReviewedSHA256
	}
	if _, e = PlanStage(req, inventory, *fresh, p.Preparation, p.Certificates); e != nil {
		t.Fatal("fresh review with immutable certificate/profile origin rejected")
	}
	if _, e = PlanStage(req, inventory, *old, p.Preparation, p.Certificates); e == nil {
		t.Fatal("stale full inspection receipt accepted")
	}
}
func TestPhysicalBindingsChangeMaterialIdentity(t *testing.T) {
	f := fixture(t)
	before, e := f.inspect()
	if e != nil {
		t.Fatal("inspection")
	}
	for _, name := range []string{"tenant", "import", "native-node", "source-node", "host"} {
		t.Run(name, func(t *testing.T) {
			plan := f.plan
			r := before.Receipt
			switch name {
			case "tenant":
				plan.TenantID = tlsIdentity
			case "import":
				plan.ImportID = tlsIdentity
			case "native-node":
				plan.NodeID = tlsIdentity
			case "source-node":
				plan.SourceNodeID = tlsIdentity
			case "host":
				plan.ExpectedHostname = "elsewhere"
				r.Hostname = "elsewhere"
			}
			if materialDigest(plan, r) == before.MaterialSHA256 {
				t.Fatal("physical binding absent from material digest")
			}
		})
	}
}
func TestPlanningRejectsSourceAndReceiptDrift(t *testing.T) {
	for _, name := range []string{"review", "source", "missing-domain", "missing-mount", "hostname", "source-enabled", "inbound-id", "native-id", "clients", "dependencies", "public-key", "cutover-claim", "adoption", "missing-adoption", "extra-certificate"} {
		t.Run(name, func(t *testing.T) {
			f, req, inventory, _ := planningFixture(t)
			i, e := f.inspect()
			if e != nil {
				t.Fatal("inspection")
			}
			p := plannedPreparation(f, t)
			switch name {
			case "review":
				req.ReviewedSHA256 = strings.Repeat("0", 64)
			case "source":
				req.SourceNodeID = tlsIdentity
			case "missing-domain":
				req.TLSDomains = nil
			case "missing-mount":
				req.Mounts = nil
			case "hostname":
				req.ExpectedHostname = "other"
			case "source-enabled":
				p.Preparation.Services[1].Enabled = true
			case "inbound-id":
				p.Preparation.Services[1].InboundID = identity
			case "native-id":
				p.Preparation.Services[1].Service.ID = identity
			case "clients":
				p.Preparation.Services[0].Service.Clients = []model.ClientSpec{{ID: identity, StatsKey: tlsIdentity}}
			case "dependencies":
				i.Receipt.Dependencies.Interfaces = []string{}
			case "public-key":
				for n := range i.Receipt.Materials {
					if i.Receipt.Materials[n].Security == "reality" {
						i.Receipt.Materials[n].RealityPublicKeySHA256 = strings.Repeat("0", 64)
					}
				}
			case "cutover-claim":
				i.Receipt.CutoverReady = true
			case "adoption":
				p.Certificates[0].AdoptionSHA256 = strings.Repeat("0", 64)
			case "missing-adoption":
				p.Certificates[0].AdoptionSHA256 = ""
			case "extra-certificate":
				c := p.Certificates[0]
				c.CertificateID = identity
				p.Certificates = append(p.Certificates, c)
			}
			// A forged receipt may recalculate its own hashes; source cross-checks must
			// still reject altered keys, dependencies and claimed cutover readiness.
			i.SHA256 = digest(encoded(i.Receipt))
			i.MaterialSHA256 = materialDigest(f.plan, i.Receipt)
			if _, e = PlanStage(req, inventory, *i, p.Preparation, p.Certificates); e == nil {
				t.Fatal("inconsistent plan accepted")
			}
		})
	}
	_, req, raw, _ := planningFixture(t)
	req.Mounts[0].HostPath = "/owner-audited-path-only-on-original-node"
	if _, e := PlanInspection(req, raw); e != nil {
		t.Fatal("planner tried reading remote mount on CP")
	}
}
func TestSourceTemplateJSONExcludesPrivateGraph(t *testing.T) {
	f, req, inventory, sensitive := planningFixture(t)
	s, e := xrayprofile.ExportSourceTemplate(inventory, req.SourceNodeID)
	if e != nil {
		t.Fatal("export")
	}
	data := encoded(s)
	if bytes.Contains(data, []byte(f.private)) || bytes.Contains(data, []byte(sensitive)) || bytes.Contains(data, []byte("certificateFile")) {
		t.Fatal("private graph leaked through JSON")
	}
	if len(s.Requirements) != 2 || s.Requirements[1].Enabled {
		t.Fatal("source requirement lost")
	}
}
