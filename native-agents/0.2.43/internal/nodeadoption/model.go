package nodeadoption

import (
	"errors"
	"time"
	"vpn-platform/internal/xrayprofile"
)

var ErrMaterial = errors.New("source material or reviewed adoption plan does not match")
var ErrOutput = errors.New("adoption output is unavailable or differs from the verified bundle")

type Mount struct {
	ContainerPath string `json:"container_path"`
	HostPath      string `json:"host_path"`
}
type Domain struct {
	InboundTag string `json:"inbound_tag"`
	Domain     string `json:"domain"`
}
type InspectionPlan struct {
	Version            int      `json:"version"`
	TenantID           string   `json:"tenant_id"`
	ImportID           string   `json:"import_id"`
	NodeID             string   `json:"node_id"`
	SourceNodeID       string   `json:"source_node_id"`
	ReviewedSHA256     string   `json:"reviewed_sha256"`
	SourceConfigSHA256 string   `json:"source_config_sha256"`
	ExpectedHostname   string   `json:"expected_hostname"`
	Mounts             []Mount  `json:"mounts"`
	TLSDomains         []Domain `json:"tls_domains"`
}

// Preparation is the existing prepare-held-xray response, not a desired state.
type Preparation struct {
	NodeID          string                      `json:"node_id"`
	ImportID        string                      `json:"import_id"`
	InventorySHA256 string                      `json:"inventory_sha256"`
	ReviewedSHA256  string                      `json:"reviewed_sha256"`
	ProfileSHA256   string                      `json:"profile_sha256"`
	Services        []xrayprofile.SourceService `json:"services"`
	State           string                      `json:"state"`
}

// Certificate is the public prepare-held-tls response. The caller must supply
// the stable material digest as adoption_sha256 when preparing it on CP.
type Certificate struct {
	CertificateID     string    `json:"certificate_id"`
	NodeID            string    `json:"node_id"`
	InventorySHA256   string    `json:"inventory_sha256"`
	ReviewedSHA256    string    `json:"reviewed_sha256"`
	Domain            string    `json:"domain"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	ChainSHA256       string    `json:"chain_sha256"`
	NotAfter          time.Time `json:"not_after"`
	State             string    `json:"state"`
	AdoptionSHA256    string    `json:"adoption_sha256"`
}
type StagePlan struct {
	Inspection       InspectionPlan `json:"inspection"`
	InspectionSHA256 string         `json:"inspection_sha256"`
	Preparation      Preparation    `json:"preparation"`
	Certificates     []Certificate  `json:"certificates"`
}
type MaterialReceipt struct {
	InboundTag             string     `json:"inbound_tag"`
	Security               string     `json:"security"`
	RealityPublicKeySHA256 string     `json:"reality_public_key_sha256,omitempty"`
	Domain                 string     `json:"domain,omitempty"`
	FingerprintSHA256      string     `json:"fingerprint_sha256,omitempty"`
	ChainSHA256            string     `json:"chain_sha256,omitempty"`
	KeyPairVerified        bool       `json:"key_pair_verified,omitempty"`
	NotAfter               *time.Time `json:"not_after,omitempty"`
}
type InspectionReceipt struct {
	Version            int                      `json:"version"`
	Kind               string                   `json:"kind"`
	PlanSHA256         string                   `json:"plan_sha256"`
	ReviewedSHA256     string                   `json:"reviewed_sha256"`
	SourceConfigSHA256 string                   `json:"source_config_sha256"`
	Hostname           string                   `json:"hostname"`
	Materials          []MaterialReceipt        `json:"materials"`
	Dependencies       xrayprofile.Dependencies `json:"dependencies"`
	PhysicalProof      string                   `json:"physical_proof"`
	SourceStopped      bool                     `json:"source_stopped"`
	RuntimeInstalled   bool                     `json:"runtime_installed"`
	CutoverReady       bool                     `json:"cutover_ready"`
}
type Inspection struct {
	SHA256         string            `json:"sha256"`
	MaterialSHA256 string            `json:"material_sha256"`
	Receipt        InspectionReceipt `json:"receipt"`
	material       map[string]localMaterial
	plan           InspectionPlan
}
type localMaterial struct {
	source     xrayprofile.SourceMaterial
	chain, key []byte
}
type StageReceipt struct {
	Version          int                         `json:"version"`
	Kind             string                      `json:"kind"`
	PlanSHA256       string                      `json:"plan_sha256"`
	InspectionSHA256 string                      `json:"inspection_sha256"`
	ProfileSHA256    string                      `json:"profile_sha256"`
	Services         []xrayprofile.SourceService `json:"services"`
	SourceStopped    bool                        `json:"source_stopped"`
	RuntimeInstalled bool                        `json:"runtime_installed"`
	CutoverReady     bool                        `json:"cutover_ready"`
}
type Bundle struct {
	Files      map[string][]byte
	Links      map[string]string
	Inspection *Inspection
	Stage      *StageReceipt
	Planning   *PlanningReceipt
}
type Summary struct {
	Kind             string `json:"kind"`
	InspectionSHA256 string `json:"inspection_sha256,omitempty"`
	MaterialSHA256   string `json:"material_sha256,omitempty"`
	PlanSHA256       string `json:"plan_sha256,omitempty"`
	ManifestSHA256   string `json:"manifest_sha256"`
	Files            int    `json:"files"`
	Links            int    `json:"links"`
	Existing         bool   `json:"existing"`
	CutoverReady     bool   `json:"cutover_ready"`
}
