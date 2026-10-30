package model

import "time"

type VPNService struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	NodeID                  string    `json:"node_id"`
	Name                    string    `json:"name"`
	SubscriptionName        *string   `json:"subscription_name"`
	SubscriptionDefaultName string    `json:"subscription_default_name,omitempty"`
	Protocol                string    `json:"protocol"`
	Listen                  string    `json:"listen"`
	Port                    int       `json:"port"`
	Transport               string    `json:"transport"`
	Security                string    `json:"security"`
	PublicAddress           *string   `json:"public_address,omitempty"`
	PublicPort              *int      `json:"public_port,omitempty"`
	Enabled                 bool      `json:"enabled"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type VPNClientService struct {
	TenantID  string    `json:"tenant_id"`
	ClientID  string    `json:"client_id"`
	ServiceID string    `json:"service_id"`
	CreatedAt time.Time `json:"created_at"`
}
