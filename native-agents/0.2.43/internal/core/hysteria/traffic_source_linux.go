//go:build linux

package hysteria

import (
	"context"
	"os"
	"path/filepath"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

// OpenStoredTrafficSource reads existing private settings without creating or
// replacing them. It never starts/stops a unit. The stop helper may sample the
// original invocation while systemd is executing ExecStop.
func OpenStoredTrafficSource(base, unit string, stopping bool) (*Statistics, func(context.Context) (string, error), error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || os.Geteuid() != 0 {
		return nil, nil, ErrRuntimeSettings
	}
	root := filepath.Join(base, "hysteria2")
	control := filepath.Join(root, "control")
	for _, dir := range []string{base, root, control} {
		if protectedDirectory(dir, false) != nil {
			return nil, nil, ErrRuntimeSettings
		}
	}
	info, err := os.Stat(control)
	if err != nil || info.Mode().Perm() != 0700 {
		return nil, nil, ErrRuntimeSettings
	}
	raw, err := readTLSFile(filepath.Join(control, "settings.json"), 4096, 0600, -1)
	if err != nil {
		return nil, nil, ErrRuntimeSettings
	}
	var settings runtimeSettings
	if decodeStrict(raw, &settings) != nil || settings.Format != 1 || !validRuntimeIdentity(settings.UID, settings.GID) {
		return nil, nil, ErrRuntimeSettings
	}
	if _, err = compiler.CompileHysteria(model.DesiredState{Core: model.CoreRelease{Type: "hysteria2"}}, settings.options()); err != nil {
		return nil, nil, ErrRuntimeSettings
	}
	stats, err := NewStatistics(settings.StatisticsPort, settings.StatisticsSecret)
	if err != nil {
		return nil, nil, err
	}
	runtime, err := NewSystemdRuntime(unit, stats)
	if err != nil {
		return nil, nil, err
	}
	if stopping {
		return stats, runtime.CaptureInvocation, nil
	}
	return stats, runtime.Invocation, nil
}

func PrepareTrafficSource(base string, identity ManagedIdentity, unit string) (*Statistics, func(context.Context) (string, error), error) {
	if _, err := openRuntimeSettings(base, identity.UID, identity.GID); err != nil {
		return nil, nil, err
	}
	return OpenStoredTrafficSource(base, unit, false)
}
