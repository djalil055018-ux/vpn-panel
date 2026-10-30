package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const rollbackTimeout = 45 * time.Second

func checkContext(
	ctx context.Context,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()

	default:
		return nil
	}
}

func systemctlContext(
	ctx context.Context,
	args ...string,
) error {
	output, err :=
		exec.CommandContext(
			ctx,
			"systemctl",
			args...,
		).CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"systemctl %s: %w: %s",
			strings.Join(args, " "),
			err,
			string(output),
		)
	}

	return nil
}

func waitContext(
	ctx context.Context,
	duration time.Duration,
) error {
	timer :=
		time.NewTimer(duration)

	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()

	case <-timer.C:
		return nil
	}
}

func (d *Driver) StopContext(
	ctx context.Context,
) error {
	if err :=
		checkContext(ctx); err != nil {

		return err
	}
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}

	output, err :=
		exec.CommandContext(
			ctx,
			"systemctl",
			"stop",
			"vpn-platform-xray.service",
		).CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"stop xray: %w: %s",
			err,
			string(output),
		)
	}

	return checkContext(ctx)
}

func (d *Driver) HealthContext(
	ctx context.Context,
) (bool, error) {
	if err := d.CheckAccessFence(); err != nil {
		return false, err
	}
	if err :=
		checkContext(ctx); err != nil {

		return false, err
	}

	if d.CurrentVersion() == "" {
		return false, nil
	}

	err :=
		exec.CommandContext(
			ctx,
			"systemctl",
			"is-active",
			"--quiet",
			"vpn-platform-xray.service",
		).Run()

	if ctx.Err() != nil {
		return false,
			ctx.Err()
	}

	if err != nil {
		return false, nil
	}

	return true, nil
}

func (d *Driver) StartContext(
	ctx context.Context,
) error {
	if err := d.CheckAccessFence(); err != nil {
		return err
	}
	if err :=
		systemctlContext(
			ctx,
			"enable",
			"vpn-platform-xray.service",
		); err != nil {

		return err
	}

	if err :=
		systemctlContext(
			ctx,
			"start",
			"vpn-platform-xray.service",
		); err != nil {

		return err
	}

	if err :=
		waitContext(
			ctx,
			time.Second,
		); err != nil {

		return err
	}

	healthy, err :=
		d.HealthContext(ctx)

	if err != nil {
		return err
	}

	if !healthy {
		return fmt.Errorf(
			"xray service did not become healthy",
		)
	}

	return nil
}

func (d *Driver) RollbackContext(
	ctx context.Context,
	snapshot string,
) error {
	if f, err := d.readAccessFence(); err != nil && !os.IsNotExist(err) {
		return err
	} else if f.Blocked {
		return ErrAccessFence
	}
	if err :=
		checkContext(ctx); err != nil {

		return err
	}

	dir :=
		filepath.Join(
			d.snapshotDir(),
			snapshot,
		)

	raw, err :=
		os.ReadFile(
			filepath.Join(
				dir,
				"metadata.json",
			),
		)

	if err != nil {
		return err
	}

	if err :=
		checkContext(ctx); err != nil {

		return err
	}

	var metadata snapshotMetadata

	if err :=
		json.Unmarshal(
			raw,
			&metadata,
		); err != nil {

		return err
	}

	if err :=
		d.StopContext(ctx); err != nil {

		return err
	}

	if err :=
		checkContext(ctx); err != nil {

		return err
	}

	config, configErr :=
		os.ReadFile(
			filepath.Join(
				dir,
				"config.json",
			),
		)

	if configErr == nil {
		if err :=
			checkContext(ctx); err != nil {

			return err
		}

		if err :=
			d.ApplyConfig(
				config,
			); err != nil {

			return err
		}
	}

	if err :=
		checkContext(ctx); err != nil {

		return err
	}

	if metadata.Version == "" {
		_ = os.Remove(
			d.currentLink(),
		)

		if err :=
			systemctlContext(
				ctx,
				"disable",
				"vpn-platform-xray.service",
			); err != nil {

			return err
		}

		return nil
	}

	if err :=
		d.Activate(
			metadata.Version,
		); err != nil {

		return err
	}

	if err :=
		checkContext(ctx); err != nil {

		return err
	}

	return d.StartContext(ctx)
}

func rollbackContext() (
	context.Context,
	context.CancelFunc,
) {
	return context.WithTimeout(
		context.Background(),
		rollbackTimeout,
	)
}
