package model

type TenantResourceLimits struct {
	TenantID   string `json:"tenant_id"`
	MaxClients int    `json:"max_clients"`
	MaxPlans   int    `json:"max_plans"`
	Clients    int    `json:"clients"`
	Plans      int    `json:"plans"`
}
