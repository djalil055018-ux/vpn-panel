package model

import "time"

type RegisteredDevice struct {
	ID             string    `json:"id"`
	IdentifierHint string    `json:"identifier_hint"`
	Platform       *string   `json:"platform"`
	OSVersion      *string   `json:"os_version"`
	Model          *string   `json:"model"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

type RegisteredDevices struct {
	Limit   int                `json:"limit"`
	Count   int                `json:"count"`
	Devices []RegisteredDevice `json:"devices"`
}
