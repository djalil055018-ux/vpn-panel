package model

import "time"

type AuditEventMetadata struct {
	ID             string    `json:"id"`
	TenantID       *string   `json:"tenant_id"`
	NodeID         *string   `json:"node_id"`
	EventType      string    `json:"event_type"`
	ActorType      string    `json:"actor_type"`
	ActorID        *string   `json:"actor_id"`
	CreatedAt      time.Time `json:"created_at"`
	RequestID      *string   `json:"request_id"`
	RequestOutcome *string   `json:"request_outcome"`
	HTTPStatus     *int      `json:"http_status"`
}
type AuditCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}
type AuditHistory struct {
	Events     []AuditEventMetadata `json:"events"`
	NextCursor *AuditCursor         `json:"-"`
}
