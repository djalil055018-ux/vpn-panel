package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

type BootstrapInspection struct {
	NodeID      string `json:"node_id"`
	RuntimeCore string `json:"runtime_core"`
}

// Reading a bootstrap's own safe identity never rotates or consumes it.
func (p *Postgres) InspectNodeBootstrap(ctx context.Context, hash string) (BootstrapInspection, error) {
	var out BootstrapInspection
	err := p.Pool.QueryRow(ctx, `SELECT id::text,runtime_core FROM nodes WHERE bootstrap_token_hash=$1 AND bootstrap_used_at IS NULL AND agent_token_hash IS NULL`, hash).Scan(&out.NodeID, &out.RuntimeCore)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}
