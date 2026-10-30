package model

import "time"

type ResellerChild struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"created_at"`
	ClientCount  int       `json:"client_count"`
	ServiceCount int       `json:"service_count"`
}
