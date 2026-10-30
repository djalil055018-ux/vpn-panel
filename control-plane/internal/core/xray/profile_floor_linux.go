//go:build linux

package xray

import (
	"context"
	"vpn-platform/internal/core"
	"vpn-platform/internal/model"
)

func (d *Driver) requireProfileRuntime(ctx context.Context, state model.DesiredState) error {
	if state.XrayCascades != nil {
		return core.RequireXrayCascadeRuntime(ctx, d.BaseDir)
	}
	if state.XrayProfile == nil {
		return nil
	}
	return core.RequireXrayProfileRuntime(ctx, d.BaseDir)
}
