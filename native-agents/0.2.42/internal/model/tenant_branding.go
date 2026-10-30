package model

type TenantBranding struct {
	TenantID     string `json:"tenant_id"`
	DisplayName  string `json:"display_name"`
	Tagline      string `json:"tagline"`
	SupportLabel string `json:"support_label"`
	SupportURL   string `json:"support_url"`
	Accent       string `json:"accent"`
}
