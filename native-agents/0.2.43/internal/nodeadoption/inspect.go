package nodeadoption

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"regexp"
	"sort"
	"time"

	"vpn-platform/internal/xrayprofile"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var dnsPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func encoded(v any) []byte     { raw, _ := json.Marshal(v); return raw }

// pem.Decode may skip malformed leading blocks. An inspection must account for
// every byte, so decode exactly the first block before considering the next.
func firstPEM(raw []byte) (*pem.Block, []byte) {
	end := bytes.Index(raw, []byte("-----END "))
	if end < 0 {
		return nil, nil
	}
	stop := bytes.IndexByte(raw[end:], '\n')
	if stop < 0 {
		stop = len(raw)
	} else {
		stop += end + 1
	}
	first := raw[:stop]
	if bytes.Count(first, []byte("-----BEGIN ")) != 1 {
		return nil, nil
	}
	block, rest := pem.Decode(first)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil
	}
	return block, raw[stop:]
}

func verifyPair(domain string, chain, key []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, string, error) {
	if len(domain) > 253 || !dnsPattern.MatchString(domain) || len(chain) == 0 || len(chain) > 65536 || len(key) == 0 || len(key) > 65536 {
		return nil, "", ErrMaterial
	}
	rest := bytes.TrimSpace(chain)
	certs := []*x509.Certificate{}
	sum := sha256.New()
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) || len(certs) >= 8 {
			return nil, "", ErrMaterial
		}
		block, tail := firstPEM(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, "", ErrMaterial
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, "", ErrMaterial
		}
		certs = append(certs, cert)
		sum.Write(cert.Raw)
		rest = bytes.TrimSpace(tail)
	}
	if len(certs) == 0 || certs[0].IsCA {
		return nil, "", ErrMaterial
	}
	intermediate := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		if certs[i-1].CheckSignatureFrom(certs[i]) != nil {
			return nil, "", ErrMaterial
		}
		intermediate.AddCert(certs[i])
	}
	if _, e := certs[0].Verify(x509.VerifyOptions{DNSName: domain, CurrentTime: now, Roots: roots, Intermediates: intermediate, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return nil, "", ErrMaterial
	}
	private := bytes.TrimSpace(key)
	block, tail := firstPEM(private)
	if block == nil || len(block.Headers) > 0 || len(bytes.TrimSpace(tail)) != 0 || !bytes.HasPrefix(private, []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, "", ErrMaterial
	}
	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, "", ErrMaterial
	}
	if _, e := tls.X509KeyPair(chain, key); e != nil {
		return nil, "", ErrMaterial
	}
	return certs[0], hex.EncodeToString(sum.Sum(nil)), nil
}

// Inspect performs only bounded local reads. It cannot prove the source daemon
// identity, socket access, interface availability or single-writer handoff.
func Inspect(plan InspectionPlan, raw []byte) (*Inspection, error) {
	host, e := os.Hostname()
	if e != nil {
		return nil, ErrMaterial
	}
	return inspect(plan, raw, host, nil, time.Now())
}
func inspect(plan InspectionPlan, raw []byte, host string, roots *x509.CertPool, now time.Time) (*Inspection, error) {
	if plan.Version != 1 || plan.ExpectedHostname == "" || plan.ExpectedHostname != host || len(raw) > 4<<20 || digest(raw) != plan.SourceConfigSHA256 || !hashPattern.MatchString(plan.ReviewedSHA256) || !validMounts(plan.Mounts) {
		return nil, ErrMaterial
	}
	for _, id := range []string{plan.TenantID, plan.ImportID, plan.NodeID, plan.SourceNodeID} {
		if !idPattern.MatchString(id) {
			return nil, ErrMaterial
		}
	}
	materials, deps, e := xrayprofile.InspectSourceMaterials(raw)
	if e != nil || len(materials) == 0 || len(materials) > 128 {
		return nil, ErrMaterial
	}
	domains := map[string]string{}
	for _, d := range plan.TLSDomains {
		if d.InboundTag == "" || domains[d.InboundTag] != "" || !dnsPattern.MatchString(d.Domain) {
			return nil, ErrMaterial
		}
		domains[d.InboundTag] = d.Domain
	}
	receipt := InspectionReceipt{Version: 1, Kind: "node-material-inspection", PlanSHA256: digest(encoded(plan)), ReviewedSHA256: plan.ReviewedSHA256, SourceConfigSHA256: plan.SourceConfigSHA256, Hostname: host, Dependencies: deps, PhysicalProof: "owner_local_files"}
	result := &Inspection{material: map[string]localMaterial{}, plan: plan}
	domainChains := map[string]string{}
	for _, m := range materials {
		local := localMaterial{source: m}
		item := MaterialReceipt{InboundTag: m.InboundTag, Security: m.Security}
		if m.Security == "reality" {
			item.RealityPublicKeySHA256 = digest([]byte(m.RealityPublicKey))
		} else {
			domain := domains[m.InboundTag]
			if domain == "" {
				return nil, ErrMaterial
			}
			delete(domains, m.InboundTag)
			local.chain, e = readMounted(plan.Mounts, m.Local.CertificateFile)
			if e != nil {
				return nil, ErrMaterial
			}
			local.key, e = readMounted(plan.Mounts, m.Local.KeyFile)
			if e != nil {
				return nil, ErrMaterial
			}
			leaf, chainSHA, e := verifyPair(domain, local.chain, local.key, roots, now)
			if e != nil {
				return nil, ErrMaterial
			}
			item.Domain = domain
			item.FingerprintSHA256 = digest(leaf.Raw)
			item.ChainSHA256 = chainSHA
			item.KeyPairVerified = true
			item.NotAfter = &leaf.NotAfter
			if old := domainChains[domain]; old != "" && old != chainSHA {
				return nil, ErrMaterial
			}
			domainChains[domain] = chainSHA
		}
		result.material[m.InboundTag] = local
		receipt.Materials = append(receipt.Materials, item)
	}
	if len(domains) != 0 {
		return nil, ErrMaterial
	}
	sort.Slice(receipt.Materials, func(i, j int) bool { return receipt.Materials[i].InboundTag < receipt.Materials[j].InboundTag })
	result.Receipt = receipt
	result.SHA256 = digest(encoded(receipt))
	result.MaterialSHA256 = materialDigest(plan, receipt)
	return result, nil
}

// Bind the physical material to this tenant/import/node and source template,
// without binding it to unrelated user counters in the full inventory. The
// complete receipt SHA still binds the current reviewed inventory separately.
func materialDigest(plan InspectionPlan, receipt InspectionReceipt) string {
	plan.ReviewedSHA256 = ""
	receipt.ReviewedSHA256 = ""
	receipt.PlanSHA256 = ""
	return digest(encoded(struct {
		Kind    string
		Plan    InspectionPlan
		Receipt InspectionReceipt
	}{"node-material-attestation-v1", plan, receipt}))
}
func (i *Inspection) PublicBundle() *Bundle {
	b := &Bundle{Files: map[string][]byte{"inspection.json": encoded(i)}, Links: map[string]string{}, Inspection: i}
	for _, m := range i.Receipt.Materials {
		if m.Security == "tls" {
			b.Files["public-certificates/"+m.ChainSHA256+".pem"] = i.material[m.InboundTag].chain
			request := TLSPreparationRequest{TenantID: i.plan.TenantID, NodeID: i.plan.NodeID, SourceNodeID: i.plan.SourceNodeID, Domain: m.Domain, FullchainPEM: string(i.material[m.InboundTag].chain), AdoptionSHA256: i.MaterialSHA256}
			b.Files["prepare-tls/"+digest([]byte(m.Domain))+".json"] = encoded(request)
		}
	}
	return b
}
