package model

import "time"

type BackupStatus struct {
	ID             string     `json:"id"`
	Status         string     `json:"status"`
	LastSuccessAt  *time.Time `json:"last_success_at"`
	LastVerifiedAt *time.Time `json:"last_verified_at"`
	SizeBytes      int64      `json:"size_bytes"`
	Verification   string     `json:"verification"`
	FreeBytes      int64      `json:"free_bytes"`
	ReportedAt     *time.Time `json:"reported_at,omitempty"`
}
type OperationsNode struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Lifecycle       NodeLifecycleStatus     `json:"lifecycle"`
	Backup          *BackupStatus           `json:"backup"`
	Metrics         *NodeMetricPoint        `json:"metrics,omitempty"`
	TrafficDelivery *TrafficDeliveryReceipt `json:"traffic_delivery,omitempty"`
}
type OperationsStatus struct {
	WebhookQueue          *WebhookQueueStatus `json:"webhook_queue"`
	RestoreDrill          *RestoreDrillStatus `json:"restore_drill"`
	PendingAccessNodes    int                 `json:"pending_access_nodes"`
	GeneratedAt           time.Time           `json:"generated_at"`
	Nodes                 []OperationsNode    `json:"nodes"`
	ControlPlaneBackup    *BackupStatus       `json:"control_plane_backup"`
	ControlPlaneFreeBytes int64               `json:"control_plane_free_bytes"`
	ExpiringCertificates  int                 `json:"expiring_certificates"`
	ExpiredCertificates   int                 `json:"expired_certificates"`
	FailedCertificates    int                 `json:"failed_certificates"`
	AttentionCertificates int                 `json:"attention_certificates"`
	ClientDeviceWarnings  []ClientDeviceUsage `json:"client_device_warnings"`
}

type ClientDeviceUsage struct {
	ClientID    string `json:"client_id"`
	ClientName  string `json:"client_name"`
	ActiveIPs   int    `json:"active_ips"`
	DeviceLimit int    `json:"device_limit"`
}

type WebhookQueueStatus struct {
	GeneratedAt       time.Time  `json:"generated_at"`
	LastDispatchAt    *time.Time `json:"last_dispatch_at"`
	EnabledEndpoints  int        `json:"enabled_endpoints"`
	PendingDeliveries int        `json:"pending_deliveries"`
	OverdueDeliveries int        `json:"overdue_deliveries"`
	FailedDeliveries  int        `json:"failed_deliveries"`
}

type RestoreDrillStatus struct {
	Status              string     `json:"status"`
	BackupID            string     `json:"backup_id"`
	VerifiedAt          *time.Time `json:"verified_at"`
	CheckedAt           *time.Time `json:"checked_at"`
	ControlPlaneVersion string     `json:"control_plane_version"`
	WebPages            int        `json:"web_pages"`
	DurationSeconds     int        `json:"duration_seconds"`
	Verification        string     `json:"verification"`
}
