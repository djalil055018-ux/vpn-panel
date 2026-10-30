package xray

import (
	"context"
	"os"
	"time"
	"vpn-platform/internal/model"
)

// Restore only the exact healthy assignment confirmed by the control plane.
// The Agent owns Xray's service lifetime, so stopping/restarting the Agent also
// stops Xray; an unblocked committed generation must be able to start again.
func (d *Driver) RestoreTerminalAssignment(ctx context.Context, a model.AgentAssignment) error {
	if a.DeploymentStatus != "healthy" || a.FenceRequest != nil || a.NodeAppliedGeneration != a.DesiredState.Generation || a.DesiredState.Core.Type != "xray" || a.AppliedCoreVersion != a.DesiredState.Core.Version || d.CurrentVersion() != a.AppliedCoreVersion {
		return ErrAccessFence
	}
	intent, err := d.accessIntent(a.DesiredState)
	if err != nil {
		return err
	}
	fence, err := d.readAccessFence()
	if os.IsNotExist(err) {
		// A pre-fence agent has no durable native receipt. Recompile and validate the
		// confirmed assignment through normal reconciliation before creating one.
		return d.Reconcile(ctx, a.DesiredState)
	}
	if err != nil || fence.Blocked || fence.Generation != intent.Generation || fence.Digest != intent.Digest {
		return ErrAccessFence
	}
	if err = d.CheckAccessFence(); err != nil {
		return err
	}
	if err = d.checkProfileDependencies(ctx, a.DesiredState.XrayProfile); err != nil {
		return err
	}
	if err = d.requireProfileRuntime(ctx, a.DesiredState); err != nil {
		return err
	}
	if healthy, e := d.HealthContext(ctx); e != nil {
		return e
	} else if healthy {
		return nil
	}
	if err = d.StartContext(ctx); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = d.StopContext(cleanup)
		return err
	}
	return nil
}
