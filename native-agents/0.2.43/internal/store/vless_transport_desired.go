package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

// Applies to raw desired-state submissions and recovery as well as service rebuilds.
func validateVLESSTransportDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState) error {
	// The preceding admission gate checks the registered graph, parser floor,
	// release approval and exact native membership in the same transaction.
	if state.XrayProfile != nil {
		return xrayprofile.ValidateServices(state.XrayProfile, state.Services)
	}
	for _, service := range state.Services {
		if service.Transport != "ws" && service.Transport != "grpc" {
			continue
		}
		if state.Core.Type != "xray" || service.Protocol != "vless" || service.Security != "tls" || service.TLS == nil {
			return errors.New("VLESS WS/gRPC requires Xray and TLS")
		}
		var compatible bool
		err := tx.QueryRow(ctx, `SELECT CASE WHEN agent_version ~ '^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$' THEN string_to_array(agent_version,'.')::int[] >= ARRAY[0,2,26] ELSE false END FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&compatible)
		if err != nil {
			return err
		}
		if !compatible {
			return errors.New("VLESS WS/gRPC requires Agent 0.2.26 or newer")
		}
	}
	return nil
}
