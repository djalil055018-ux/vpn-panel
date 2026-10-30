package model

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Empty input resets an override. Emoji, flags and ordinary punctuation are
// allowed; a label must stay on one line in every supported subscription format.
func ValidSubscriptionName(name string) bool {
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 200 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func (c VPNClientConnection) DisplayName() string {
	if name := strings.TrimSpace(c.SubscriptionName); name != "" {
		return name
	}
	brand := strings.TrimSpace(c.BrandName)
	if brand == "" {
		brand = "PAUK"
	}
	if service := strings.TrimSpace(c.ServiceName); service != "" {
		return brand + " - " + service
	}
	return brand
}
