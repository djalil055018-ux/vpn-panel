package nodeadoption

import (
	"path"
	"reflect"
	"regexp"
	"sort"
	"time"

	"vpn-platform/internal/xrayprofile"
)

// These mappings come from an owner audit of the target node. Planning on CP
// neither discovers Docker mounts nor asserts that the paths exist there.
type PlanningRequest struct {
	Version          int      `json:"version"`
	TenantID         string   `json:"tenant_id"`
	ImportID         string   `json:"import_id"`
	NodeID           string   `json:"node_id"`
	SourceNodeID     string   `json:"source_node_id"`
	ReviewedSHA256   string   `json:"reviewed_sha256"`
	ExpectedHostname string   `json:"expected_hostname"`
	Mounts           []Mount  `json:"mounts"`
	TLSDomains       []Domain `json:"tls_domains"`
}
type PlanningReceipt struct {
	Version            int    `json:"version"`
	Kind               string `json:"kind"`
	RequestSHA256      string `json:"request_sha256"`
	InventorySHA256    string `json:"inventory_sha256"`
	SourceProfileID    string `json:"source_profile_id"`
	SourceConfigSHA256 string `json:"source_config_sha256"`
	PlanSHA256         string `json:"plan_sha256"`
	SourceStopped      bool   `json:"source_stopped"`
	RuntimeInstalled   bool   `json:"runtime_installed"`
	CutoverReady       bool   `json:"cutover_ready"`
}
type TLSPreparationRequest struct {
	TenantID       string `json:"tenant_id"`
	NodeID         string `json:"node_id"`
	SourceNodeID   string `json:"source_node_id"`
	Domain         string `json:"domain"`
	FullchainPEM   string `json:"fullchain_pem"`
	AdoptionSHA256 string `json:"adoption_sha256"`
}
type TLSAssignment struct {
	SourceInboundID string `json:"source_inbound_id"`
	CertificateID   string `json:"certificate_id"`
}
type CertificateResponse struct {
	Preparation   Certificate `json:"preparation"`
	PhysicalProof string      `json:"physical_proof"`
	CutoverReady  bool        `json:"cutover_ready"`
}

func DecodeCertificateResponses(raw []byte) ([]Certificate, error) {
	var responses []CertificateResponse
	if DecodePlan(raw, &responses) != nil || responses == nil || len(responses) > 128 {
		return nil, ErrMaterial
	}
	result := []Certificate{}
	for _, r := range responses {
		if r.PhysicalProof != "owner_attestation" || r.CutoverReady {
			return nil, ErrMaterial
		}
		result = append(result, r.Preparation)
	}
	return result, nil
}

type XrayPreparationRequest struct {
	TenantID       string          `json:"tenant_id"`
	NodeID         string          `json:"node_id"`
	SourceNodeID   string          `json:"source_node_id"`
	TLSAssignments []TLSAssignment `json:"tls_assignments"`
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func inspectionPlan(request PlanningRequest, inventory []byte) (InspectionPlan, *xrayprofile.SourceTemplate, error) {
	var zero InspectionPlan
	if request.Version != 1 || !hashPattern.MatchString(request.ReviewedSHA256) || !hostPattern.MatchString(request.ExpectedHostname) || len(request.Mounts) > 128 {
		return zero, nil, ErrMaterial
	}
	for _, id := range []string{request.TenantID, request.ImportID, request.NodeID, request.SourceNodeID} {
		if !idPattern.MatchString(id) {
			return zero, nil, ErrMaterial
		}
	}
	seen := map[string]bool{}
	for _, m := range request.Mounts {
		if !path.IsAbs(m.ContainerPath) || path.Clean(m.ContainerPath) != m.ContainerPath || !path.IsAbs(m.HostPath) || path.Clean(m.HostPath) != m.HostPath || seen[m.ContainerPath] {
			return zero, nil, ErrMaterial
		}
		seen[m.ContainerPath] = true
	}
	source, e := xrayprofile.ExportSourceTemplate(inventory, request.SourceNodeID)
	if e != nil || source.InventorySHA256 != request.ReviewedSHA256 {
		return zero, nil, ErrMaterial
	}
	domains := map[string]string{}
	for _, d := range request.TLSDomains {
		if d.InboundTag == "" || domains[d.InboundTag] != "" || len(d.Domain) > 253 || !dnsPattern.MatchString(d.Domain) {
			return zero, nil, ErrMaterial
		}
		domains[d.InboundTag] = d.Domain
	}
	for _, r := range source.Requirements {
		if r.Security == "tls" {
			if domains[r.Tag] == "" {
				return zero, nil, ErrMaterial
			}
			delete(domains, r.Tag)
		}
	}
	if len(domains) != 0 {
		return zero, nil, ErrMaterial
	}
	// Every source TLS path must have an explicit container-to-host mapping even
	// when preparing on CP, where the physical host directories are unavailable.
	materials, _, e := xrayprofile.InspectSourceMaterials(source.Config)
	if e != nil {
		return zero, nil, ErrMaterial
	}
	for _, m := range materials {
		if m.Security == "tls" {
			for _, name := range []string{m.Local.CertificateFile, m.Local.KeyFile} {
				found := false
				for _, mount := range request.Mounts {
					if mount.ContainerPath == "/" || len(name) > len(mount.ContainerPath) && name[:len(mount.ContainerPath)+1] == mount.ContainerPath+"/" {
						found = true
					}
				}
				if !found {
					return zero, nil, ErrMaterial
				}
			}
		}
	}
	return InspectionPlan{Version: 1, TenantID: request.TenantID, ImportID: request.ImportID, NodeID: request.NodeID, SourceNodeID: request.SourceNodeID, ReviewedSHA256: request.ReviewedSHA256, SourceConfigSHA256: source.ConfigSHA256, ExpectedHostname: request.ExpectedHostname, Mounts: request.Mounts, TLSDomains: request.TLSDomains}, source, nil
}
func planningBundle(kind string, request PlanningRequest, source *xrayprofile.SourceTemplate, plan any, filename string) *Bundle {
	receipt := &PlanningReceipt{Version: 1, Kind: kind, RequestSHA256: digest(encoded(request)), InventorySHA256: source.InventorySHA256, SourceProfileID: source.SourceProfileID, SourceConfigSHA256: source.ConfigSHA256, PlanSHA256: digest(encoded(plan))}
	return &Bundle{Planning: receipt, Links: map[string]string{}, Files: map[string][]byte{
		filename: encoded(plan), "source-config.json": source.Config, "source-requirements.json": encoded(source), "planning-receipt.json": encoded(receipt),
	}}
}

// PlanInspection exports only this node's graph, not the full inventory of
// subscriber credentials. source-config.json is private and must stay private.
func PlanInspection(request PlanningRequest, inventory []byte) (*Bundle, error) {
	plan, source, e := inspectionPlan(request, inventory)
	if e != nil {
		return nil, e
	}
	return planningBundle("node-inspection-plan", request, source, plan, "inspection-plan.json"), nil
}

func verifiedInspection(plan InspectionPlan, source *xrayprofile.SourceTemplate, i Inspection) bool {
	if i.SHA256 != digest(encoded(i.Receipt)) || i.MaterialSHA256 != materialDigest(plan, i.Receipt) {
		return false
	}
	materials, deps, e := xrayprofile.InspectSourceMaterials(source.Config)
	if e != nil || len(i.Receipt.Materials) != len(materials) {
		return false
	}
	actual := map[string]MaterialReceipt{}
	for _, m := range i.Receipt.Materials {
		if _, duplicate := actual[m.InboundTag]; duplicate {
			return false
		}
		actual[m.InboundTag] = m
	}
	domains := map[string]string{}
	for _, d := range plan.TLSDomains {
		domains[d.InboundTag] = d.Domain
	}
	expected := InspectionReceipt{Version: 1, Kind: "node-material-inspection", PlanSHA256: digest(encoded(plan)), ReviewedSHA256: plan.ReviewedSHA256, SourceConfigSHA256: plan.SourceConfigSHA256, Hostname: plan.ExpectedHostname, Dependencies: deps, PhysicalProof: "owner_local_files"}
	for _, m := range materials {
		got, ok := actual[m.InboundTag]
		if !ok {
			return false
		}
		item := MaterialReceipt{InboundTag: m.InboundTag, Security: m.Security}
		if m.Security == "reality" {
			item.RealityPublicKeySHA256 = digest([]byte(m.RealityPublicKey))
		} else {
			if !hashPattern.MatchString(got.FingerprintSHA256) || !hashPattern.MatchString(got.ChainSHA256) || got.NotAfter == nil || !got.NotAfter.After(time.Now()) {
				return false
			}
			item.Domain = domains[m.InboundTag]
			item.KeyPairVerified = true
			item.FingerprintSHA256 = got.FingerprintSHA256
			item.ChainSHA256 = got.ChainSHA256
			item.NotAfter = got.NotAfter
		}
		expected.Materials = append(expected.Materials, item)
	}
	sort.Slice(expected.Materials, func(a, b int) bool { return expected.Materials[a].InboundTag < expected.Materials[b].InboundTag })
	return reflect.DeepEqual(expected, i.Receipt)
}

// PlanStage checks CP's native bindings against the exact reviewed source,
// including disabled inbounds and transport settings. CP responses still need
// an authenticated owner channel; these JSON copies are not signatures.
func PlanStage(request PlanningRequest, inventory []byte, i Inspection, p Preparation, certificates []Certificate) (*Bundle, error) {
	plan, source, e := inspectionPlan(request, inventory)
	if e != nil || !verifiedInspection(plan, source, i) || p.State != "prepared" || p.NodeID != request.NodeID || p.ImportID != request.ImportID || p.ReviewedSHA256 != request.ReviewedSHA256 || !hashPattern.MatchString(p.InventorySHA256) || len(p.Services) != len(source.Requirements) {
		return nil, ErrMaterial
	}
	assignments := []xrayprofile.SourceServiceAssignment{}
	for _, s := range p.Services {
		assignments = append(assignments, xrayprofile.SourceServiceAssignment{InboundID: s.InboundID, ServiceID: s.Service.ID, TLS: s.Service.TLS})
	}
	projected, e := xrayprofile.ProjectSourceNode(inventory, request.SourceNodeID, assignments)
	if e != nil || projected.Profile.SHA256 != p.ProfileSHA256 || !reflect.DeepEqual(projected.Services, p.Services) {
		return nil, ErrMaterial
	}
	certs := map[string]Certificate{}
	used := map[string]bool{}
	for _, c := range certificates {
		if _, exists := certs[c.CertificateID]; exists || !idPattern.MatchString(c.CertificateID) || c.State != "prepared" || c.NodeID != p.NodeID || c.ReviewedSHA256 != p.ReviewedSHA256 || !hashPattern.MatchString(c.InventorySHA256) || c.AdoptionSHA256 != i.MaterialSHA256 {
			return nil, ErrMaterial
		}
		certs[c.CertificateID] = c
	}
	inspected := map[string]MaterialReceipt{}
	for _, m := range i.Receipt.Materials {
		inspected[m.InboundTag] = m
	}
	for _, s := range p.Services {
		if s.Service.TLS != nil {
			c, ok := certs[s.Service.TLS.CertificateID]
			m := inspected[s.InboundTag]
			if !ok || c.Domain != s.Service.TLS.ServerName || c.Domain != m.Domain || c.FingerprintSHA256 != m.FingerprintSHA256 || c.ChainSHA256 != m.ChainSHA256 || m.NotAfter == nil || !c.NotAfter.Equal(*m.NotAfter) {
				return nil, ErrMaterial
			}
			used[c.CertificateID] = true
		}
	}
	if len(used) != len(certs) {
		return nil, ErrMaterial
	}
	stage := StagePlan{Inspection: plan, InspectionSHA256: i.SHA256, Preparation: p, Certificates: certificates}
	return planningBundle("node-stage-plan", request, source, stage, "stage-plan.json"), nil
}

// PlanPreparation joins the public certificate responses to source inbound IDs.
// It produces the existing owner API request, but never sends it or creates IDs.
func PlanPreparation(request PlanningRequest, inventory []byte, i Inspection, certificates []Certificate) (*Bundle, error) {
	plan, source, e := inspectionPlan(request, inventory)
	if e != nil || !verifiedInspection(plan, source, i) {
		return nil, ErrMaterial
	}
	byDomain := map[string]Certificate{}
	ids := map[string]bool{}
	for _, c := range certificates {
		if _, exists := byDomain[c.Domain]; exists || ids[c.CertificateID] || !idPattern.MatchString(c.CertificateID) || c.State != "prepared" || c.NodeID != request.NodeID || c.ReviewedSHA256 != request.ReviewedSHA256 || !hashPattern.MatchString(c.InventorySHA256) || c.AdoptionSHA256 != i.MaterialSHA256 {
			return nil, ErrMaterial
		}
		byDomain[c.Domain] = c
		ids[c.CertificateID] = true
	}
	inspected := map[string]MaterialReceipt{}
	for _, m := range i.Receipt.Materials {
		inspected[m.InboundTag] = m
	}
	out := XrayPreparationRequest{TenantID: request.TenantID, NodeID: request.NodeID, SourceNodeID: request.SourceNodeID, TLSAssignments: []TLSAssignment{}}
	used := map[string]bool{}
	for _, r := range source.Requirements {
		if r.Security == "tls" {
			m := inspected[r.Tag]
			c, ok := byDomain[m.Domain]
			if !ok || c.FingerprintSHA256 != m.FingerprintSHA256 || c.ChainSHA256 != m.ChainSHA256 || m.NotAfter == nil || !c.NotAfter.Equal(*m.NotAfter) {
				return nil, ErrMaterial
			}
			out.TLSAssignments = append(out.TLSAssignments, TLSAssignment{SourceInboundID: r.ID, CertificateID: c.CertificateID})
			used[c.CertificateID] = true
		}
	}
	if len(used) != len(certificates) {
		return nil, ErrMaterial
	}
	return planningBundle("node-xray-preparation-plan", request, source, out, "prepare-xray-node.json"), nil
}
