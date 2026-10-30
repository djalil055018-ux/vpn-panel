package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/xrayprofile"
)

var ErrImportedTLS = errors.New("imported TLS certificate or prepared node differs from reviewed material")
var importedTLSDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type ImportedTLSRequest struct {
	TenantID       string `json:"tenant_id"`
	NodeID         string `json:"node_id"`
	SourceNodeID   string `json:"source_node_id"`
	Domain         string `json:"domain"`
	FullchainPEM   string `json:"fullchain_pem"`
	AdoptionSHA256 string `json:"adoption_sha256"`
}
type ImportedTLSPreparation struct {
	AdoptionSHA256    string    `json:"adoption_sha256"`
	CertificateID     string    `json:"certificate_id"`
	NodeID            string    `json:"node_id"`
	InventorySHA256   string    `json:"inventory_sha256"`
	ReviewedSHA256    string    `json:"reviewed_sha256"`
	Domain            string    `json:"domain"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	ChainSHA256       string    `json:"chain_sha256"`
	NotAfter          time.Time `json:"not_after"`
	State             string    `json:"state"`
}

// Production always uses system roots; tests may supply an isolated synthetic CA.
// No private-key block, arbitrary prefix, malformed tail or unrelated chain is accepted.
func verifyImportedTLS(domain, material string, roots *x509.CertPool, now time.Time) (*x509.Certificate, string, error) {
	if len(domain) > 253 || !importedTLSDomain.MatchString(domain) || len(material) == 0 || len(material) > 65536 {
		return nil, "", ErrImportedTLS
	}
	remaining := bytes.TrimSpace([]byte(material))
	chain := []*x509.Certificate{}
	digest := sha256.New()
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) || len(chain) >= 8 {
			return nil, "", ErrImportedTLS
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, "", ErrImportedTLS
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, "", ErrImportedTLS
		}
		chain = append(chain, cert)
		digest.Write(cert.Raw)
		remaining = bytes.TrimSpace(rest)
	}
	if len(chain) == 0 || chain[0].IsCA {
		return nil, "", ErrImportedTLS
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		if chain[i-1].CheckSignatureFrom(chain[i]) != nil {
			return nil, "", ErrImportedTLS
		}
		intermediates.AddCert(chain[i])
	}
	if _, e := chain[0].Verify(x509.VerifyOptions{DNSName: domain, CurrentTime: now, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return nil, "", ErrImportedTLS
	}
	return chain[0], hex.EncodeToString(digest.Sum(nil)), nil
}

func (p *Postgres) PrepareImportedTLS(ctx context.Context, importID, reviewedSHA string, req ImportedTLSRequest) (ImportedTLSPreparation, error) {
	return p.prepareImportedTLS(ctx, importID, reviewedSHA, req, nil)
}

// This records an owner's physical-adoption attestation, not an independent SSH
// proof. Runtime activation must verify that receipt and native on-node keypair.
// The existing certificate is retained; Let's Encrypt is the future renewal
// provider. Renewal remains disabled and fenced until physical node activation.
func (p *Postgres) prepareImportedTLS(ctx context.Context, importID, reviewedSHA string, req ImportedTLSRequest, roots *x509.CertPool) (out ImportedTLSPreparation, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	for _, id := range []string{importID, req.TenantID, req.NodeID, req.SourceNodeID} {
		if !xrayPreparationUUID.MatchString(id) {
			return out, ErrImportedTLS
		}
	}
	if !xrayPreparationDigest.MatchString(reviewedSHA) || !xrayPreparationDigest.MatchString(req.AdoptionSHA256) {
		return out, ErrImportedTLS
	}
	leaf, chainSHA, err := verifyImportedTLS(req.Domain, req.FullchainPEM, roots, time.Now())
	if err != nil {
		return out, err
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	out = ImportedTLSPreparation{AdoptionSHA256: req.AdoptionSHA256, NodeID: req.NodeID, InventorySHA256: reviewedSHA, ReviewedSHA256: reviewedSHA, Domain: req.Domain, FingerprintSHA256: hex.EncodeToString(fingerprint[:]), ChainSHA256: chainSHA, NotAfter: leaf.NotAfter, State: "prepared"}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	defer func() {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && (pe.Code == "23505" || pe.Code == "23503" || pe.Code == "23514") {
			err = ErrImportedTLS
		}
	}()
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid AND state='held'`, importID, req.TenantID).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, origin); err != nil {
		return out, err
	}
	if err = lockTenantResource(ctx, tx, req.TenantID); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, req.TenantID); err != nil {
		return out, err
	}
	var raw []byte
	var digest string
	err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256 FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held' FOR UPDATE OF h`, importID, req.TenantID).Scan(&raw, &digest)
	if err != nil {
		return out, err
	}
	if digest != reviewedSHA {
		return out, ErrRemnawaveReview
	}
	requirements, e := xrayprofile.SourceNodeRequirements(raw, req.SourceNodeID)
	if e != nil {
		return out, ErrImportedTLS
	}
	tlsFound := false
	for _, r := range requirements {
		if r.Security == "tls" {
			tlsFound = true
		}
	}
	if !tlsFound {
		return out, ErrImportedTLS
	}
	// Match preparation's certificate-before-node lock order.
	var oldImport, oldSource, oldChain, oldAdoption, oldFingerprint, status string
	var renew bool
	err = tx.QueryRow(ctx, `SELECT c.id::text,t.import_id::text,t.source_node_id::text,t.inventory_sha256,t.chain_sha256,t.adoption_sha256,coalesce(c.fingerprint_sha256,''),c.status,c.auto_renew
 FROM imported_tls_certificates t JOIN node_certificates c ON c.id=t.certificate_id WHERE t.node_id=$1::uuid AND t.domain=$2 FOR UPDATE OF c`, req.NodeID, req.Domain).Scan(&out.CertificateID, &oldImport, &oldSource, &out.InventorySHA256, &oldChain, &oldAdoption, &oldFingerprint, &status, &renew)
	existing := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if existing && (oldImport != importID || oldSource != req.SourceNodeID || oldChain != chainSHA || oldAdoption != req.AdoptionSHA256 || oldFingerprint != out.FingerprintSHA256 || status != "active" || renew) {
		return out, ErrImportedTLS
	}
	var runtime string
	var generation int64
	err = tx.QueryRow(ctx, `SELECT runtime_core,desired_generation FROM nodes WHERE id=$1::uuid AND tenant_id=$2::uuid AND applied_generation=0 AND NOT EXISTS(SELECT 1 FROM node_retirements WHERE node_id=nodes.id) FOR UPDATE`, req.NodeID, req.TenantID).Scan(&runtime, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if runtime != "xray" || generation != 0 {
		return out, ErrImportedTLS
	}
	var drift bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM desired_states WHERE node_id=$1::uuid) OR EXISTS(SELECT 1 FROM deployments WHERE node_id=$1::uuid)
 OR EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE node_id=$1::uuid)
 OR EXISTS(SELECT 1 FROM vpn_services WHERE node_id=$1::uuid AND enabled)
 OR EXISTS(SELECT 1 FROM certificate_jobs WHERE node_id=$1::uuid AND status IN ('pending','claimed'))
 OR EXISTS(SELECT 1 FROM node_xray_profiles WHERE node_id=$1::uuid AND (import_id<>$2::uuid OR source_node_id<>$3::uuid OR state<>'prepared'))
 OR EXISTS(SELECT 1 FROM imported_tls_certificates WHERE node_id=$1::uuid AND (import_id<>$2::uuid OR source_node_id<>$3::uuid))`, req.NodeID, importID, req.SourceNodeID).Scan(&drift)
	if err != nil {
		return out, err
	}
	if drift {
		return out, ErrImportedTLS
	}
	if existing {
		return out, tx.Commit(ctx)
	}
	err = tx.QueryRow(ctx, `WITH identity AS (SELECT gen_random_uuid() id) INSERT INTO node_certificates(id,tenant_id,node_id,domain,provider,challenge_type,environment,status,auto_renew,certificate_ref,issuer,fingerprint_sha256,not_before,not_after,observed_at)
 SELECT id,$1::uuid,$2::uuid,$3,'letsencrypt','http-01','production','active',false,'certificates/'||id::text,$4,$5,$6,$7,now() FROM identity RETURNING id::text`, req.TenantID, req.NodeID, req.Domain, leaf.Issuer.String(), out.FingerprintSHA256, leaf.NotBefore, leaf.NotAfter).Scan(&out.CertificateID)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO imported_tls_certificates(certificate_id,node_id,tenant_id,import_id,inventory_sha256,source_node_id,domain,chain_sha256,fingerprint_sha256,adoption_sha256) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6::uuid,$7,$8,$9,$10)`, out.CertificateID, req.NodeID, req.TenantID, importID, reviewedSHA, req.SourceNodeID, req.Domain, chainSHA, out.FingerprintSHA256, req.AdoptionSHA256)
	if err != nil {
		return out, err
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$6::uuid,'imported_tls.prepared',$2,$3,jsonb_build_object('certificate_id',$4::text,'import_id',$5::text,'node_id',$6::text,'inventory_sha256',$7::text,'adoption_sha256',$8::text,'chain_sha256',$9::text,'physical_proof','owner_attestation','auto_renew',false))`, req.TenantID, actor, actorID, out.CertificateID, importID, req.NodeID, reviewedSHA, req.AdoptionSHA256, chainSHA)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func importedTLSRenewalHeld(ctx context.Context, q xrayProfileQuery, id string) (bool, error) {
	var held bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM imported_tls_certificates c WHERE c.certificate_id=$1::uuid AND NOT EXISTS(SELECT 1 FROM node_xray_profiles p WHERE p.node_id=c.node_id AND p.import_id=c.import_id AND p.source_node_id=c.source_node_id AND p.state='active'))`, id).Scan(&held)
	return held, err
}
