package model

import "time"

type NodeCertificate struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	NodeID            string     `json:"node_id"`
	Domain            string     `json:"domain"`
	Provider          string     `json:"provider"`
	ChallengeType     string     `json:"challenge_type"`
	Environment       string     `json:"environment"`
	ContactEmail      *string    `json:"contact_email,omitempty"`
	Status            string     `json:"status"`
	AutoRenew         bool       `json:"auto_renew"`
	CertificateRef    string     `json:"certificate_ref"`
	Issuer            *string    `json:"issuer,omitempty"`
	FingerprintSHA256 *string    `json:"fingerprint_sha256,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	ObservedAt        *time.Time `json:"observed_at,omitempty"`
	LastError         *string    `json:"last_error,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
