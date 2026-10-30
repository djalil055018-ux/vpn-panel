package model

import "time"

type NodeMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	Load1         float64 `json:"load_1"`
	MemoryTotal   int64   `json:"memory_total_bytes"`
	MemoryUsed    int64   `json:"memory_used_bytes"`
	DiskTotal     int64   `json:"disk_total_bytes"`
	DiskUsed      int64   `json:"disk_used_bytes"`
	NetworkRX     int64   `json:"network_rx_bytes"`
	NetworkTX     int64   `json:"network_tx_bytes"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

type NodeMetricPoint struct {
	SampledAt     time.Time `json:"sampled_at"`
	CPUPercent    float64   `json:"cpu_percent"`
	Load1         float64   `json:"load_1"`
	MemoryTotal   int64     `json:"memory_total_bytes"`
	MemoryUsed    int64     `json:"memory_used_bytes"`
	DiskTotal     int64     `json:"disk_total_bytes"`
	DiskUsed      int64     `json:"disk_used_bytes"`
	NetworkRX     int64     `json:"network_rx_bytes"`
	NetworkTX     int64     `json:"network_tx_bytes"`
	UptimeSeconds int64     `json:"uptime_seconds"`
}

type NodeMetricSeries struct {
	NodeID      string            `json:"node_id"`
	From        time.Time         `json:"from"`
	To          time.Time         `json:"to"`
	StepSeconds int               `json:"step_seconds"`
	Points      []NodeMetricPoint `json:"points"`
}

type ClientTraffic struct {
	ClientID  string `json:"client_id"`
	Uplink    int64  `json:"uplink_bytes"`
	Downlink  int64  `json:"downlink_bytes"`
	ActiveIPs int    `json:"active_ips"`
	// Omission preserves the older Xray wire format. True means the runtime
	// cannot measure distinct addresses; ActiveIPs must then remain zero.
	ActiveIPsUnavailable bool `json:"active_ips_unavailable,omitempty"`
}

// A node persists Sequence before collecting. Epoch identifies one Xray service
// invocation, independently of how often the reporting agent restarts.
type ClientTrafficSnapshot struct {
	Epoch    string          `json:"epoch"`
	Sequence int64           `json:"sequence"`
	Clients  []ClientTraffic `json:"clients"`
}

type VPNClientUsage struct {
	ClientID          string     `json:"client_id"`
	PeriodStart       time.Time  `json:"period_start"`
	UplinkBytes       int64      `json:"uplink_bytes"`
	DownlinkBytes     int64      `json:"downlink_bytes"`
	UsedBytes         int64      `json:"used_bytes"`
	MonthlyLimitBytes int64      `json:"monthly_limit_bytes"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	ResetPolicy       string     `json:"reset_policy"`
	ImportedBytes     int64      `json:"imported_bytes"`
	RemainingBytes    int64      `json:"remaining_bytes"`
	QuotaExceeded     bool       `json:"quota_exceeded"`
	ActiveIPs         *int       `json:"active_ips"`
	DeviceLimit       int        `json:"device_limit"`
	DeviceWarning     bool       `json:"device_warning"`
	LastObservedAt    *time.Time `json:"last_observed_at,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
