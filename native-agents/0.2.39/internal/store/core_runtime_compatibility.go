package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

func (p *Postgres) coreRuntimeCompatible(ctx context.Context, nodeID, coreType string) (bool, error) {
	var runtime, agent, os, version, arch string
	err := p.Pool.QueryRow(ctx, `SELECT runtime_core,COALESCE(agent_version,''),COALESCE(os_name,''),COALESCE(os_version,''),COALESCE(architecture,'') FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&runtime, &agent, &os, &version, &arch)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if runtime != coreType {
		return false, ErrNodeRuntime
	}
	if runtime == "wireguard" {
		return model.NativeWireGuardAgentCompatible(agent) && os == "ubuntu" && version == "24.04" && arch == "amd64", nil
	}
	if runtime == "pptp" {
		return model.PPTPAgentCompatible(agent) && os == "ubuntu" && version == "24.04" && arch == "amd64", nil
	}
	if runtime == "openvpn" {
		return model.OpenVPNAgentCompatible(agent) && os == "ubuntu" && version == "24.04" && arch == "amd64", nil
	}
	return runtime != "hysteria2" || (HysteriaAgentOperationallyCompatible(agent) && os == "ubuntu" && version == "24.04" && arch == "amd64"), nil
}

func reviewedRuntimeArtifact(core, version, sha, url string) bool {
	if core == "wireguard" {
		return version == model.WireGuardNativeVersion && sha == model.WireGuardPinnedSHA256 && url == model.WireGuardPinnedDownloadURL
	}
	if core == "pptp" {
		return version == model.PPTPPinnedVersion && sha == model.PPTPPinnedSHA256 && url == model.PPTPPinnedDownloadURL
	}
	if core == "openvpn" {
		return version == model.OpenVPNPinnedVersion && sha == model.OpenVPNPinnedSHA256 && url == model.OpenVPNPinnedDownloadURL
	}
	return core != "hysteria2" || (version == model.HysteriaPinnedVersion && sha == model.HysteriaPinnedSHA256 && url == model.HysteriaPinnedDownloadURL)
}

// Revalidate existing approvals with current node facts. The node and reviewed
// release remain locked until approval or execution commits.
func rolloutRuntimeCompatibleTx(ctx context.Context, tx pgx.Tx, plan model.RolloutPlan) (bool, error) {
	var runtime, agent, os, version, arch string
	err := tx.QueryRow(ctx, `SELECT runtime_core,COALESCE(agent_version,''),COALESCE(os_name,''),COALESCE(os_version,''),COALESCE(architecture,'') FROM nodes WHERE id=$1::uuid FOR UPDATE`, plan.NodeID).Scan(&runtime, &agent, &os, &version, &arch)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if runtime != plan.CoreType {
		return false, nil
	}
	if runtime == "openvpn" || runtime == "wireguard" || runtime == "pptp" {
		return false, nil
	} // System-package updates require a reviewed installer release.
	if runtime != "hysteria2" {
		return true, nil
	}
	if !HysteriaAgentOperationallyCompatible(agent) || os != "ubuntu" || version != "24.04" || arch != "amd64" {
		return false, nil
	}
	if plan.TargetCoreReleaseID == "" {
		return false, nil
	}
	var core, releaseVersion, sha, url string
	var approved, revoked bool
	err = tx.QueryRow(ctx, `SELECT core_type,version,sha256,download_url,approved,revoked FROM core_releases WHERE id=$1::uuid FOR SHARE`, plan.TargetCoreReleaseID).Scan(&core, &releaseVersion, &sha, &url, &approved, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return core == runtime && approved && !revoked && reviewedRuntimeArtifact(core, releaseVersion, sha, url), nil
}
