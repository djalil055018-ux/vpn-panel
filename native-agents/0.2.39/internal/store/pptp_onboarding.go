package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

// Import makes the reviewed artifact discoverable without approving deployment.
func (p *Postgres) ImportReviewedPPTP(ctx context.Context) (model.CoreReleaseRecord, bool, error) {
	return p.ImportCoreRelease(ctx, model.CoreReleaseRecord{Type: "pptp", Version: model.PPTPPinnedVersion, OS: "linux", Architecture: "amd64", DownloadURL: model.PPTPPinnedDownloadURL, SHA256: model.PPTPPinnedSHA256, Channel: "testing"}, `{"source":"platform_reviewed_pptp_pin"}`)
}

func (p *Postgres) ApproveReviewedPPTP(ctx context.Context) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var id string
	var approved bool
	err = tx.QueryRow(ctx, `SELECT id::text,approved FROM core_releases WHERE core_type='pptp' AND version=$1 AND os='linux' AND architecture='amd64' AND sha256=$2 AND download_url=$3 AND NOT revoked FOR UPDATE`, model.PPTPPinnedVersion, model.PPTPPinnedSHA256, model.PPTPPinnedDownloadURL).Scan(&id, &approved)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPinnedCoreReleaseUnavailable
	}
	if err != nil {
		return err
	}
	if approved {
		return tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `UPDATE core_releases SET approved=true,approved_at=now(),approved_by='control-plane',updated_at=now() WHERE id=$1::uuid`, id)
	if err != nil {
		return err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload) VALUES('core_release.approved',$1,$2,jsonb_build_object('core_release_id',$3::text,'reviewed_runtime','pptp'))`, actorType, actorID, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Initialize never replaces an existing desired state. Node locking makes retries
// and simultaneous initialization converge on one initial deployment.
func (p *Postgres) InitializePPTPRuntime(ctx context.Context, nodeID string) (model.DesiredState, bool, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.DesiredState{}, false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var runtime string
	var generation int64
	var registered bool
	err = tx.QueryRow(ctx, `SELECT runtime_core,desired_generation,agent_token_hash IS NOT NULL FROM nodes WHERE id=$1::uuid FOR UPDATE`, nodeID).Scan(&runtime, &generation, &registered)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, false, ErrNotFound
	}
	if err != nil {
		return model.DesiredState{}, false, err
	}
	if runtime != "pptp" || !registered {
		return model.DesiredState{}, false, ErrNodeRuntime
	}
	if generation > 0 {
		var raw []byte
		var state model.DesiredState
		err = tx.QueryRow(ctx, `SELECT document FROM desired_states WHERE node_id=$1::uuid AND generation=$2`, nodeID, generation).Scan(&raw)
		if err != nil {
			return state, false, err
		}
		if err = json.Unmarshal(raw, &state); err != nil {
			return state, false, err
		}
		return state, false, tx.Commit(ctx)
	}
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE node_id=$1::uuid AND enabled)`, nodeID).Scan(&enabled)
	if err != nil {
		return model.DesiredState{}, false, err
	}
	if enabled {
		return model.DesiredState{}, false, errors.New("initial runtime requires all services to be disabled")
	}
	var releaseID, channel string
	err = tx.QueryRow(ctx, `SELECT id::text,channel FROM core_releases WHERE core_type='pptp' AND version=$1 AND os='linux' AND architecture='amd64' AND sha256=$2 AND download_url=$3 AND approved AND NOT revoked FOR SHARE`, model.PPTPPinnedVersion, model.PPTPPinnedSHA256, model.PPTPPinnedDownloadURL).Scan(&releaseID, &channel)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, false, ErrPinnedCoreReleaseUnavailable
	}
	if err != nil {
		return model.DesiredState{}, false, err
	}
	state := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: "pptp", Version: model.PPTPPinnedVersion, SHA256: model.PPTPPinnedSHA256, DownloadURL: model.PPTPPinnedDownloadURL, Channel: channel}, Services: []model.ServiceSpec{}}
	if err = saveDesiredStateTx(ctx, tx, nodeID, state, releaseID); err != nil {
		return model.DesiredState{}, false, err
	}
	return state, true, tx.Commit(ctx)
}
