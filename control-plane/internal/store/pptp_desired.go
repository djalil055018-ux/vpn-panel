package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func validatePPTPDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState, releaseID string) error {
	if state.Core.Type != "pptp" {
		for _, s := range state.Services {
			if s.Protocol == "pptp" {
				return ErrNodeRuntime
			}
		}
		return nil
	}
	if state.Core.Version != model.PPTPPinnedVersion || state.Core.SHA256 != model.PPTPPinnedSHA256 || state.Core.DownloadURL != model.PPTPPinnedDownloadURL || len(state.Services) > 1 {
		return errors.New("PPTP requires the reviewed runtime and one service per node")
	}
	var agent string
	var compatible bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(agent_version,''),runtime_core='pptp' AND os_name='ubuntu' AND os_version='24.04' AND architecture='amd64' FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&agent, &compatible)
	if err != nil {
		return err
	}
	if !compatible || !model.PPTPAgentCompatible(agent) {
		return ErrNodeRuntime
	}
	var approved bool
	err = tx.QueryRow(ctx, `SELECT approved AND NOT revoked AND core_type='pptp' AND version=$2 AND sha256=$3 AND download_url=$4 AND os='linux' AND architecture='amd64' FROM core_releases WHERE id=$1::uuid FOR SHARE`, releaseID, state.Core.Version, state.Core.SHA256, state.Core.DownloadURL).Scan(&approved)
	if err != nil {
		return err
	}
	if !approved {
		return ErrPinnedCoreReleaseUnavailable
	}
	for _, s := range state.Services {
		if err = compiler.ValidatePPTPService(s); err != nil {
			return err
		}
		var owned bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE id=$1::uuid AND node_id=$2::uuid AND enabled AND protocol='pptp' AND listen=$3 AND port=$4 AND transport=$5 AND security=$6)`, s.ID, nodeID, s.Listen, s.Port, s.Transport, s.Security).Scan(&owned)
		if err != nil {
			return err
		}
		if !owned {
			return ErrNodeRuntime
		}
		for _, c := range s.Clients {
			err = tx.QueryRow(ctx, `SELECT EXISTS(
    SELECT 1 FROM vpn_clients c
    JOIN vpn_effective_client_services cs ON cs.client_id=c.id AND cs.tenant_id=c.tenant_id
    JOIN vpn_client_pptp k ON k.client_id=c.id AND k.service_id=cs.service_id AND k.tenant_id=c.tenant_id AND k.credential_uuid=c.vless_uuid
    WHERE c.id=$1::uuid AND cs.service_id=$2::uuid AND k.password=$3 AND ('10.78.0.'||k.address_index::text)=$4
    AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now())
    AND NOT vpn_client_quota_exceeded(c.id))`, c.ID, s.ID, c.PPTP.Password, c.PPTP.Address).Scan(&owned)
			if err != nil {
				return err
			}
			if !owned {
				return ErrNodeRuntime
			}
		}
	}
	return nil
}
