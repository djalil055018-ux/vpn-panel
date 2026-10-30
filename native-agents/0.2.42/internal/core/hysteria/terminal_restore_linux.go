//go:build linux

package hysteria

import (
	"context"
	"reflect"
	"vpn-platform/internal/model"
)

// RestoreHealthyDesired only restarts the exact configuration and access policy
// already confirmed healthy by the Control Plane. It cannot apply new intent or
// reinterpret a failed/rolled-back deployment as a healthy one. TLS file versions
// may differ after renewal; certificate identity/domain and core pin must match.
func (d *Driver) RestoreHealthyDesired(ctx context.Context, state model.DesiredState) error {
	return d.confirmHealthyDesired(ctx, state, true)
}

// ConfirmHealthyDesired runs only after a successful CP terminal report or a
// fresh authoritative healthy assignment. It records proof without restarting.
func (d *Driver) ConfirmHealthyDesired(ctx context.Context, state model.DesiredState) error {
	return d.confirmHealthyDesired(ctx, state, false)
}
func (d *Driver) confirmed() confirmedCheckpoint {
	return confirmedCheckpoint{d.fence.path + ".confirmed"}
}

func (d *Driver) confirmHealthyDesired(ctx context.Context, state model.DesiredState, recover bool) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	tx := d.transaction
	if err := tx.lock(ctx); err != nil {
		return err
	}
	defer func() { <-tx.gate }()
	if tx.access.closed.Load() {
		return ErrDriver
	}
	generation, _ := tx.access.policy.PendingRevocations()
	fence, err := d.fence.read(generation)
	if err != nil || generation <= 0 || generation != state.Generation || fence.Generation != state.Generation {
		return ErrDesiredFence
	}
	digest, err := desiredDigest(state)
	if err != nil || digest != fence.Digest {
		return ErrDesiredFence
	}
	expected, err := buildSnapshot(clientsForState(state))
	if err != nil || !reflect.DeepEqual(expected, tx.access.policy.current.Load()) {
		return ErrAccessConflict
	}
	current, err := tx.store.current(ctx)
	if err != nil || current == nil {
		return ErrRuntimeRevision
	}
	expectedDigest, err := structuralDigest(state)
	if err != nil {
		return err
	}
	actualDigest, err := desiredDigest(current.state)
	if err != nil || expectedDigest != actualDigest {
		return ErrRuntimeRevision
	}
	if _, err = d.confirmed().next(state.Generation, current.state); err != nil {
		return err
	}
	if recover {
		if err = tx.access.Recover(ctx); err != nil {
			return err
		}
	} else if err = tx.runtime.Ready(ctx); err != nil {
		return err
	}
	return d.confirmed().commit(ctx, state.Generation, current.state)
}

// RestoreRolledBackAssignment restores only a previously CP-confirmed structure.
// The latest access checkpoint is used as-is; credentials are never reconstructed
// from the receipt or from an older desired state. Revision metadata has generation
// zero and cannot substitute for this confirmation.
func (d *Driver) RestoreRolledBackAssignment(ctx context.Context, assignment model.AgentAssignment) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	tx := d.transaction
	if err := tx.lock(ctx); err != nil {
		return err
	}
	defer func() { <-tx.gate }()
	if tx.access.closed.Load() {
		return ErrDriver
	}
	if (assignment.DeploymentStatus != "rolled_back" && assignment.DeploymentStatus != "failed") || assignment.FenceRequest != nil || assignment.DesiredState.Core.Type != "hysteria2" || assignment.NodeAppliedGeneration <= 0 || assignment.DesiredState.Generation <= assignment.NodeAppliedGeneration {
		return ErrConfirmedRuntime
	}
	receipt, exists, err := d.confirmed().read()
	if err != nil || !exists || receipt.AppliedGeneration != assignment.NodeAppliedGeneration {
		return ErrConfirmedRuntime
	}
	if assignment.DeploymentStatus == "rolled_back" && assignment.AppliedCoreVersion != receipt.CoreVersion {
		return ErrConfirmedRuntime
	}
	if assignment.DeploymentStatus == "failed" && assignment.AppliedCoreVersion != "" {
		return ErrConfirmedRuntime
	}
	generation, _ := tx.access.policy.PendingRevocations()
	fence, err := d.fence.read(generation)
	if err != nil || generation < receipt.AppliedGeneration || generation > assignment.DesiredState.Generation || fence.Generation > assignment.DesiredState.Generation {
		return ErrDesiredFence
	}
	if fence.Generation == assignment.DesiredState.Generation {
		digest, err := desiredDigest(assignment.DesiredState)
		if err != nil || digest != fence.Digest {
			return ErrDesiredFence
		}
		if generation == fence.Generation {
			expected, err := buildSnapshot(clientsForState(assignment.DesiredState))
			if err != nil || !equalSnapshot(expected, tx.access.policy.current.Load()) {
				return ErrAccessConflict
			}
		}
	}
	current, err := tx.store.current(ctx)
	if err != nil || current == nil {
		return ErrRuntimeRevision
	}
	digest, err := structuralDigest(current.state)
	if err != nil || digest != receipt.StructureDigest || runtimeVersion(current.state) != receipt.CoreVersion {
		return ErrConfirmedRuntime
	}
	return tx.access.Recover(ctx)
}
