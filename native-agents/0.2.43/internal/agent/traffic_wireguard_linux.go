//go:build linux

package agent

import (
	"context"
	"sort"
	"time"
	"vpn-platform/internal/core/wireguard"
	"vpn-platform/internal/model"
)

func NewWireGuardTrafficCollector(driver *wireguard.Driver, sequencePath string) func(context.Context, bool) (*model.TrafficDelivery, error) {
	return func(ctx context.Context, _ bool) (*model.TrafficDelivery, error) {
		epoch, clients, err := driver.Traffic(ctx)
		if err != nil {
			return nil, err
		}
		sequence, err := reserveTrafficSequence(sequencePath)
		if err != nil {
			return nil, err
		}
		sort.Slice(clients, func(i, j int) bool { return clients[i].ClientID < clients[j].ClientID })
		return &model.TrafficDelivery{RecordedAt: time.Now().UTC(), Snapshot: model.ClientTrafficSnapshot{Epoch: epoch, Sequence: sequence, Clients: clients}}, nil
	}
}
