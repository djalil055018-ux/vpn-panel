package main

import (
	"context"
	"errors"
	"vpn-platform/internal/core/xray"
)

type certificateRuntimeRefresher func(context.Context, string, string) error

var errCertificateRuntime = errors.New("certificate runtime refresher is unavailable")

func refreshCertificateRuntime(ctx context.Context, refresh certificateRuntimeRefresher, id, domain string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if refresh == nil {
		return errCertificateRuntime
	}
	if err := refresh(ctx, id, domain); err != nil {
		return err
	}
	return ctx.Err()
}
func xrayCertificateRefresher(driver *xray.Driver) certificateRuntimeRefresher {
	return func(ctx context.Context, id, domain string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if driver == nil {
			return errCertificateRuntime
		}
		return driver.RefreshTLSCertificate(id, domain)
	}
}
func runtimeCoreType(driver terminalHealthDriver) string {
	if typed, ok := driver.(interface{ CoreType() string }); ok {
		return typed.CoreType()
	}
	// Compatibility for legacy terminal-health adapters. Every selectable runtime
	// driver supplies CoreType, so a Hysteria report never takes this fallback.
	return "xray"
}
