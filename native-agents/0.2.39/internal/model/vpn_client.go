package model

import "time"

type VPNClient struct {
	ID              string           `json:"id"`
	TenantID        string           `json:"tenant_id"`
	Name            string           `json:"name"`
	VLESSUUID       string           `json:"vless_uuid"`
	Status          string           `json:"status"`
	EffectiveStatus string           `json:"effective_status"`
	ExpiresAt       *time.Time       `json:"expires_at,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	RemnawaveHold   bool             `json:"remnawave_hold,omitempty"`
	Directory       *ClientDirectory `json:"directory,omitempty"`
}
