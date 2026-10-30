package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func validateNativeWireGuardDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState, releaseID string) error {
	var runtime, agent, osName, osVersion, arch string
	err := tx.QueryRow(ctx, `SELECT runtime_core,COALESCE(agent_version,''),COALESCE(os_name,''),COALESCE(os_version,''),COALESCE(architecture,'') FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&runtime, &agent, &osName, &osVersion, &arch)
	if err != nil {
		return err
	}
	if runtime != "wireguard" && state.Core.Type != "wireguard" && runtime != "amneziawg" && state.Core.Type != "amneziawg" {
		return nil
	}
	version, sha, url := model.WireGuardNativeVersion, model.WireGuardPinnedSHA256, model.WireGuardPinnedDownloadURL
	compatible := model.NativeWireGuardAgentCompatible(agent)
	if runtime == "amneziawg" {
		version, sha, url = model.AmneziaWGNativeVersion, model.AmneziaWGArtifactSHA256, model.AmneziaWGDownloadURL
		compatible = model.AmneziaWGAgentCompatible(agent)
	}
	if (runtime != "wireguard" && runtime != "amneziawg") || state.Core.Type != runtime || !compatible || osName != "ubuntu" || osVersion != "24.04" || arch != "amd64" {
		return ErrNodeRuntime
	}
	if state.Core.Version != version || state.Core.SHA256 != sha || state.Core.DownloadURL != url || len(state.Services) > 1 {
		return errors.New("native WireGuard requires its reviewed tools and one service per node")
	}
	var approved bool
	err = tx.QueryRow(ctx, `SELECT approved AND NOT revoked AND core_type=$5 AND version=$2 AND sha256=$3 AND download_url=$4 AND os='linux' AND architecture='amd64' FROM core_releases WHERE id=$1::uuid FOR SHARE`, releaseID, state.Core.Version, state.Core.SHA256, state.Core.DownloadURL, runtime).Scan(&approved)
	if err != nil {
		return err
	}
	if !approved {
		return ErrPinnedCoreReleaseUnavailable
	}
	for _, s := range state.Services {
		if runtime == "amneziawg" {
			_, err = compiler.CompileAmneziaWG(s)
		} else {
			_, err = compiler.CompileKernelWireGuard(s)
		}
		if err != nil {
			return err
		}
		if runtime == "amneziawg" {
			raw, e := json.Marshal(s.AmneziaWG)
			if e != nil {
				return e
			}
			var matches bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_service_amneziawg WHERE service_id=$1::uuid AND settings=$2::jsonb AND version=$3)`, s.ID, raw, s.AmneziaWG.Version).Scan(&matches)
			if err != nil {
				return err
			}
			if !matches {
				return ErrAmneziaWGConfiguration
			}
		}
		var owned bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services s JOIN vpn_service_wireguard w ON w.service_id=s.id AND w.tenant_id=s.tenant_id WHERE s.id=$1::uuid AND s.node_id=$2::uuid AND s.enabled AND s.protocol=$6 AND s.listen=$3 AND s.port=$4 AND w.private_key=$5)`, s.ID, nodeID, s.Listen, s.Port, s.WireGuard.PrivateKey, runtime).Scan(&owned)
		if err != nil {
			return err
		}
		if !owned {
			return ErrNodeRuntime
		}
		identities := map[string]bool{}
		for _, c := range s.Clients {
			if c.ID != c.StatsKey || identities[c.StatsKey] {
				return ErrNodeRuntime
			}
			identities[c.StatsKey] = true
			var index int
			err = tx.QueryRow(ctx, `SELECT w.address_index FROM vpn_client_wireguard w JOIN vpn_clients c ON c.id=w.client_id AND c.tenant_id=w.tenant_id JOIN vpn_effective_client_services e ON e.client_id=c.id AND e.tenant_id=c.tenant_id AND e.service_id=w.service_id
    WHERE w.service_id=$1::uuid AND c.id=$2::uuid AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now()) AND w.credential_uuid=c.vless_uuid AND w.public_key=$3 AND w.preshared_key=$4
    AND NOT vpn_client_quota_exceeded(c.id)`, s.ID, c.StatsKey, c.WireGuard.PublicKey, c.WireGuard.PresharedKey).Scan(&index)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNodeRuntime
			}
			if err != nil {
				return err
			}
			if wireGuardAddress(index) != c.WireGuard.Address {
				return ErrNodeRuntime
			}
		}
	}
	return nil
}
