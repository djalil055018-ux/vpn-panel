package model

import "time"

type CertificateJob struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	NodeID          string     `json:"node_id"`
	CertificateID   string     `json:"certificate_id"`
	Operation       string     `json:"operation"`
	Status          string     `json:"status"`
	OwnerInstanceID *string    `json:"owner_instance_id,omitempty"`
	LeaseExpiresAt  *time.Time `json:"lease_expires_at,omitempty"`
	Attempt         int        `json:"attempt"`
	LastError       *string    `json:"last_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ClaimedAt       *time.Time `json:"claimed_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type CertificateJobClaimRequest struct {
	OwnerInstanceID string `json:"owner_instance_id"`
}

type CertificateJobWork struct {
	JobID          string    `json:"job_id"`
	CertificateID  string    `json:"certificate_id"`
	Operation      string    `json:"operation"`
	Domain         string    `json:"domain"`
	Provider       string    `json:"provider"`
	ChallengeType  string    `json:"challenge_type"`
	Environment    string    `json:"environment"`
	ContactEmail   *string   `json:"contact_email,omitempty"`
	CertificateRef string    `json:"certificate_ref"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

type CertificateJobGrant struct {
	JobID             string    `json:"job_id"`
	CertificateID     string    `json:"certificate_id"`
	Operation         string    `json:"operation"`
	Domain            string    `json:"domain"`
	Provider          string    `json:"provider"`
	ChallengeType     string    `json:"challenge_type"`
	Environment       string    `json:"environment"`
	ContactEmail      *string   `json:"contact_email,omitempty"`
	CertificateRef    string    `json:"certificate_ref"`
	LeaseToken        string    `json:"lease_token"`
	LeaseExpiresAt    time.Time `json:"lease_expires_at"`
	RenewAfterSeconds int64     `json:"renew_after_seconds"`
}

type CertificateJobLeaseRenewRequest struct {
	JobID           string `json:"job_id"`
	OwnerInstanceID string `json:"owner_instance_id"`
	LeaseToken      string `json:"lease_token"`
}

type CertificateJobResult struct {
	JobID             string     `json:"job_id"`
	CertificateID     string     `json:"certificate_id"`
	LeaseToken        string     `json:"lease_token"`
	Success           bool       `json:"success"`
	Issuer            string     `json:"issuer,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
}

type CertificateJobLeaseGrant struct {
	LeaseExpiresAt    time.Time `json:"lease_expires_at"`
	RenewAfterSeconds int64     `json:"renew_after_seconds"`
}
