package model

import "time"

// RecordedAt is collection time, independent of delivery and health/liveness.
type TrafficDelivery struct {
	RecordedAt time.Time             `json:"recorded_at"`
	Snapshot   ClientTrafficSnapshot `json:"snapshot"`
}

type TrafficDeliveryReceipt struct {
	Sequence   int64      `json:"sequence"`
	RecordedAt *time.Time `json:"recorded_at"`
	ReceivedAt *time.Time `json:"received_at"`
}
