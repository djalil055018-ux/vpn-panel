package model

import "time"

type IncidentObservation struct {
	Rule, Resource, ResourceName, Severity string
	GraceSeconds                           int
}
type MonitoringIncident struct {
	ID             string     `json:"id"`
	Rule           string     `json:"rule"`
	Resource       string     `json:"resource"`
	ResourceName   string     `json:"resource_name"`
	Severity       string     `json:"severity"`
	ObservedSince  time.Time  `json:"observed_since"`
	LastObservedAt time.Time  `json:"last_observed_at"`
	OpenedAt       *time.Time `json:"opened_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
}
type MonitoringStatus struct {
	GeneratedAt   time.Time            `json:"generated_at"`
	LastSuccessAt *time.Time           `json:"last_success_at"`
	OpenCount     int                  `json:"open_count"`
	CriticalCount int                  `json:"critical_count"`
	Incidents     []MonitoringIncident `json:"incidents"`
}
