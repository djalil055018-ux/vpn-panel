package model

import (
	"strings"
	"unicode/utf8"
)

type AutoProfileSettings struct {
	TenantID     string `json:"tenant_id"`
	Enabled      bool   `json:"enabled"`
	Name         string `json:"name"`
	RussiaDirect bool   `json:"russia_direct"`
}

func ValidAutoProfileName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && utf8.RuneCountInString(name) <= 80 && ValidSubscriptionName(name)
}
