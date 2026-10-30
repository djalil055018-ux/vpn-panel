//go:build !linux

package xray

import (
	"context"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

func (d *Driver) checkProfileDependencies(ctx context.Context, profile *model.XrayProfileSpec) error {
	if profile != nil {
		return xrayprofile.ErrProfile
	}
	return nil
}

func (d *Driver) requireProfileRuntime(ctx context.Context, state model.DesiredState) error {
	if state.XrayCascades != nil {
		return compiler.ErrXrayCascade
	}
	return d.checkProfileDependencies(ctx, state.XrayProfile)
}
