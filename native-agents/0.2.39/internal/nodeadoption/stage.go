package nodeadoption

import (
	"bytes"
	"crypto/x509"
	"os"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

func Stage(plan StagePlan, raw []byte) (*Bundle, error) {
	host, e := os.Hostname()
	if e != nil {
		return nil, ErrMaterial
	}
	return stage(plan, raw, host, nil, time.Now())
}
func stage(plan StagePlan, raw []byte, host string, roots *x509.CertPool, now time.Time) (*Bundle, error) {
	inspection, e := inspect(plan.Inspection, raw, host, roots, now)
	p := plan.Preparation
	if e != nil || inspection.SHA256 != plan.InspectionSHA256 || p.State != "prepared" || p.NodeID != plan.Inspection.NodeID || p.ImportID != plan.Inspection.ImportID || p.ReviewedSHA256 != plan.Inspection.ReviewedSHA256 || !hashPattern.MatchString(p.InventorySHA256) || len(p.Services) != len(inspection.material) {
		return nil, ErrMaterial
	}
	bindings := []model.XrayProfileBinding{}
	definitions := []model.ServiceSpec{}
	sourceIDs := map[string]bool{}
	for _, entry := range p.Services {
		s := entry.Service
		if !idPattern.MatchString(entry.InboundID) || sourceIDs[entry.InboundID] || len(s.Clients) > 0 || s.Reality != nil && s.Reality.PrivateKey != "" || s.TLS != nil && (s.TLS.CertificateFile != "" || s.TLS.KeyFile != "") {
			return nil, ErrMaterial
		}
		sourceIDs[entry.InboundID] = true
		bindings = append(bindings, model.XrayProfileBinding{ServiceID: s.ID, InboundTag: entry.InboundTag})
		definitions = append(definitions, s)
	}
	profile, _, e := xrayprofile.Project(raw, bindings)
	if e != nil || profile.SHA256 != p.ProfileSHA256 || xrayprofile.ValidateServices(profile, definitions) != nil {
		return nil, ErrMaterial
	}
	certs := map[string]Certificate{}
	used := map[string]bool{}
	for _, c := range plan.Certificates {
		if !idPattern.MatchString(c.CertificateID) || c.State != "prepared" || c.NodeID != p.NodeID || c.ReviewedSHA256 != p.ReviewedSHA256 || !hashPattern.MatchString(c.InventorySHA256) || c.AdoptionSHA256 != inspection.MaterialSHA256 {
			return nil, ErrMaterial
		}
		if _, ok := certs[c.CertificateID]; ok {
			return nil, ErrMaterial
		}
		certs[c.CertificateID] = c
	}
	materials := map[string]MaterialReceipt{}
	for _, m := range inspection.Receipt.Materials {
		materials[m.InboundTag] = m
	}
	b := inspection.PublicBundle()
	for _, entry := range p.Services {
		s := entry.Service
		m, ok := inspection.material[entry.InboundTag]
		if !ok {
			return nil, ErrMaterial
		}
		if s.Security == "reality" {
			b.Files["node-data/secrets/reality/"+s.ID+".key"] = []byte(m.source.Local.RealityPrivateKey + "\n")
			continue
		}
		c, ok := certs[s.TLS.CertificateID]
		r := materials[entry.InboundTag]
		if !ok || c.Domain != s.TLS.ServerName || c.Domain != r.Domain || c.FingerprintSHA256 != r.FingerprintSHA256 || c.ChainSHA256 != r.ChainSHA256 || r.NotAfter == nil || !c.NotAfter.Equal(*r.NotAfter) {
			return nil, ErrMaterial
		}
		used[c.CertificateID] = true
		base := "node-data/certificates/" + c.CertificateID
		for name, data := range map[string][]byte{"fullchain.pem": m.chain, "private.key": m.key} {
			target := base + "/versions/" + c.ChainSHA256 + "/" + name
			if old, exists := b.Files[target]; exists && !bytes.Equal(old, data) {
				return nil, ErrMaterial
			}
			b.Files[target] = data
		}
		b.Links[base+"/current"] = "versions/" + c.ChainSHA256
	}
	if len(used) != len(certs) {
		return nil, ErrMaterial
	}
	receipt := &StageReceipt{Version: 1, Kind: "node-material-stage", PlanSHA256: digest(encoded(plan)), InspectionSHA256: inspection.SHA256, ProfileSHA256: profile.SHA256, Services: p.Services}
	b.Stage = receipt
	b.Files["stage.json"] = encoded(receipt)
	b.Files["profile.json"] = encoded(profile)
	return b, nil
}
