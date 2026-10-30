package store

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

// Caller holds the node row lock. All service, plan and direct desired-state
// changes pass through this gate in the same transaction as their mutation.
func validateHysteriaDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState, releaseID string) error {
	if state.Core.Type != "hysteria2" {
		return nil // Existing Xray validation and database runtime guard remain in force.
	}
	if err := compiler.ValidateHysteriaDesired(state); err != nil {
		return err
	}
	if state.Core.Version != model.HysteriaPinnedVersion || state.Core.SHA256 != model.HysteriaPinnedSHA256 || state.Core.DownloadURL != model.HysteriaPinnedDownloadURL {
		return fmt.Errorf("Hysteria requires the reviewed pinned release")
	}
	var agentVersion string
	var compatible bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(agent_version,''),runtime_core='hysteria2' AND COALESCE(os_name,'')='ubuntu' AND COALESCE(os_version,'')='24.04' AND COALESCE(architecture,'')='amd64' FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&agentVersion, &compatible)
	if err != nil {
		return err
	}
	if !compatible || !HysteriaAgentOperationallyCompatible(agentVersion) {
		return ErrNodeRuntime
	}
	// The share lock serializes approval/revocation with this acceptance. Metadata
	// supplied in a desired document cannot bypass registry approval or pinning.
	var approved bool
	err = tx.QueryRow(ctx, `SELECT approved AND NOT revoked AND core_type='hysteria2' AND version=$2 AND sha256=$3 AND download_url=$4 AND os='linux' AND architecture='amd64' FROM core_releases WHERE id=$1::uuid FOR SHARE`, releaseID, state.Core.Version, state.Core.SHA256, state.Core.DownloadURL).Scan(&approved)
	if err != nil {
		return err
	}
	if !approved {
		return ErrPinnedCoreReleaseUnavailable
	}
	for _, service := range state.Services {
		var valid bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_certificates c JOIN nodes n ON n.id=c.node_id AND n.tenant_id=c.tenant_id WHERE c.id=$1::uuid AND c.node_id=$2::uuid AND c.domain=$3 AND c.environment='production' AND c.status IN ('active','renewing') AND c.not_before<=now() AND c.not_after>now())`, service.TLS.CertificateID, nodeID, service.TLS.ServerName).Scan(&valid)
		if err != nil {
			return err
		}
		if !valid {
			return ErrVPNServiceTLSInvalid
		}
	}
	return nil
}
