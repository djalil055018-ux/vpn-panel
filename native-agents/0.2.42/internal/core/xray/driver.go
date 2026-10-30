package xray

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

type Driver struct {
	BaseDir    string
	BeforeStop func(context.Context)
}

type snapshotMetadata struct {
	Version string `json:"version"`
}

func New(baseDir string) *Driver {
	return &Driver{
		BaseDir: baseDir,
	}
}

func (d *Driver) coresDir() string {
	return filepath.Join(
		d.BaseDir,
		"cores",
		"xray",
	)
}

func (d *Driver) versionDir(version string) string {
	return filepath.Join(
		d.coresDir(),
		version,
	)
}

func (d *Driver) binary(version string) string {
	return filepath.Join(
		d.versionDir(version),
		"xray",
	)
}

func (d *Driver) currentLink() string {
	return filepath.Join(
		d.coresDir(),
		"current",
	)
}

func (d *Driver) currentBinary() string {
	return filepath.Join(
		d.currentLink(),
		"xray",
	)
}

func (d *Driver) xrayDir() string {
	return filepath.Join(
		d.BaseDir,
		"xray",
	)
}

func (d *Driver) configPath() string {
	return filepath.Join(
		d.xrayDir(),
		"config.json",
	)
}

func (d *Driver) snapshotDir() string {
	return filepath.Join(
		d.BaseDir,
		"snapshots",
	)
}

func (d *Driver) Init() error {
	for _, path := range []string{
		d.BaseDir,
		filepath.Join(d.BaseDir, "cores"),
		d.coresDir(),
		d.xrayDir(),
		d.snapshotDir(),
	} {
		if err := os.MkdirAll(
			path,
			0755,
		); err != nil {
			return err
		}

		// MkdirAll does not change permissions of an existing
		// directory. Core runtime directories must remain
		// traversable by the dedicated Xray service account.
		if err := os.Chmod(
			path,
			0755,
		); err != nil {
			return err
		}
	}

	if err := d.ensureUser(); err != nil {
		return err
	}

	if err := d.ensureService(); err != nil {
		return err
	}
	if err := d.CheckAccessFence(); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return d.StopContext(ctx)
	}
	return nil
}

func (d *Driver) ensureUser() error {
	if err := exec.Command(
		"id",
		"vpnplatform-xray",
	).Run(); err == nil {
		return nil
	}

	output, err := exec.Command(
		"useradd",
		"--system",
		"--home",
		"/nonexistent",
		"--shell",
		"/usr/sbin/nologin",
		"vpnplatform-xray",
	).CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"create xray user: %w: %s",
			err,
			string(output),
		)
	}

	return nil
}

func (d *Driver) ensureService() error {
	const service = `[Unit]
Description=VPN Platform Managed Xray
After=network-online.target vpn-platform-node-agent.service
BindsTo=vpn-platform-node-agent.service
Wants=network-online.target

[Service]
Type=simple
User=vpnplatform-xray
Group=vpnplatform-xray

ExecStartPre=+/usr/local/bin/vpn-node-agent xray-runtime-check
ExecStart=/var/lib/vpn-platform/cores/xray/current/xray run -config /var/lib/vpn-platform/xray/config.json

Restart=on-failure
RestartSec=2

NoNewPrivileges=true

CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

	path := "/etc/systemd/system/vpn-platform-xray.service"

	current, _ := os.ReadFile(path)

	if string(current) != service {
		if err := os.WriteFile(
			path,
			[]byte(service),
			0644,
		); err != nil {
			return err
		}

		output, err := exec.Command(
			"systemctl",
			"daemon-reload",
		).CombinedOutput()

		if err != nil {
			return fmt.Errorf(
				"systemd reload: %w: %s",
				err,
				string(output),
			)
		}
	}

	return nil
}

func (d *Driver) Installed(version string) bool {
	info, err := os.Stat(
		d.binary(version),
	)

	return err == nil &&
		info.Mode().IsRegular()
}

func (d *Driver) Install(
	ctx context.Context,
	release model.CoreRelease,
) error {

	if release.Type != "xray" {
		return fmt.Errorf(
			"xray driver cannot install %s",
			release.Type,
		)
	}

	if release.Version == "" {
		return fmt.Errorf(
			"xray version is empty",
		)
	}

	if d.Installed(release.Version) {
		return nil
	}

	tempFile, err := os.CreateTemp(
		"",
		"vpn-platform-xray-*.zip",
	)
	if err != nil {
		return err
	}

	tempPath := tempFile.Name()
	tempFile.Close()

	defer os.Remove(tempPath)

	client := &http.Client{
		Timeout: 3 * time.Minute,
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		release.DownloadURL,
		nil,
	)
	if err != nil {
		return err
	}

	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(
			"xray download: %w",
			err,
		)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"xray download returned %s",
			response.Status,
		)
	}

	out, err := os.OpenFile(
		tempPath,
		os.O_WRONLY|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return err
	}

	if _, err := io.Copy(
		out,
		response.Body,
	); err != nil {
		out.Close()
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	if err := verifySHA256(
		tempPath,
		release.SHA256,
	); err != nil {
		return err
	}

	target := d.versionDir(
		release.Version,
	)

	tempTarget := target + ".installing"

	_ = os.RemoveAll(tempTarget)

	if err := os.MkdirAll(
		tempTarget,
		0755,
	); err != nil {
		return err
	}

	// The Node Agent runs with UMask=0077. MkdirAll's requested
	// mode is therefore not sufficient: a newly created core
	// directory would otherwise become 0700 and the dedicated
	// vpnplatform-xray runtime user could not traverse it.
	if err := os.Chmod(
		tempTarget,
		0755,
	); err != nil {
		_ = os.RemoveAll(tempTarget)
		return err
	}

	if err := extractBinary(
		tempPath,
		tempTarget,
	); err != nil {

		_ = os.RemoveAll(tempTarget)
		return err
	}

	binary := filepath.Join(
		tempTarget,
		"xray",
	)

	if err := os.Chmod(
		binary,
		0755,
	); err != nil {

		_ = os.RemoveAll(tempTarget)
		return err
	}

	output, err := exec.CommandContext(
		ctx,
		binary,
		"version",
	).CombinedOutput()

	if err != nil {
		_ = os.RemoveAll(tempTarget)

		return fmt.Errorf(
			"xray binary verification: %w: %s",
			err,
			string(output),
		)
	}

	if err := os.Rename(
		tempTarget,
		target,
	); err != nil {

		_ = os.RemoveAll(tempTarget)
		return err
	}

	return nil
}

func verifySHA256(
	path string,
	expected string,
) error {

	expected = strings.ToLower(
		strings.TrimSpace(expected),
	)

	if len(expected) != 64 {
		return fmt.Errorf(
			"invalid expected SHA-256",
		)
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(
		hash,
		file,
	); err != nil {
		return err
	}

	actual := hex.EncodeToString(
		hash.Sum(nil),
	)

	if actual != expected {
		return fmt.Errorf(
			"SHA-256 mismatch expected=%s actual=%s",
			expected,
			actual,
		)
	}

	return nil
}

// extractBinary retains the routing data shipped with the approved archive.
// Imported source profiles can depend on geoip/geosite even when the generated
// default configuration does not. Each package is extracted into a fresh,
// private version directory before Install publishes it atomically.
func extractBinary(archivePath, target string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	entries := map[string]*zip.File{}
	for _, item := range reader.File {
		if item.Name != "xray" && item.Name != "geoip.dat" && item.Name != "geosite.dat" {
			continue
		}
		if _, duplicate := entries[item.Name]; duplicate || !item.Mode().IsRegular() || item.UncompressedSize64 == 0 || item.UncompressedSize64 > 128<<20 {
			return fmt.Errorf("invalid Xray package entry")
		}
		entries[item.Name] = item
	}
	if entries["xray"] == nil {
		return fmt.Errorf("xray binary not found in archive")
	}
	// Some binary-only test/custom packages contain no geo-data. Keep those
	// compatible; native validation still rejects profiles with missing assets.
	for _, name := range []string{"xray", "geoip.dat", "geosite.dat"} {
		item := entries[name]
		if item == nil {
			continue
		}
		mode := os.FileMode(0644)
		if name == "xray" {
			mode = 0755
		}
		input, err := item.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(filepath.Join(target, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			input.Close()
			return err
		}
		n, copyErr := io.Copy(output, io.LimitReader(input, 128<<20+1))
		sourceErr := input.Close()
		modeErr := output.Chmod(mode) // Agent UMask=0077 must not hide public assets.
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if sourceErr != nil {
			return sourceErr
		}
		if n != int64(item.UncompressedSize64) || n > 128<<20 {
			return fmt.Errorf("Xray package size mismatch")
		}
		if modeErr != nil {
			return modeErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (d *Driver) Validate(
	ctx context.Context,
	version string,
	config []byte,
) error {

	temp, err := os.CreateTemp(
		d.xrayDir(),
		"candidate-*.json",
	)
	if err != nil {
		return err
	}

	path := temp.Name()

	defer os.Remove(path)

	if _, err := temp.Write(config); err != nil {
		temp.Close()
		return err
	}

	if err := temp.Close(); err != nil {
		return err
	}

	output, err := exec.CommandContext(
		ctx,
		d.binary(version),
		"run",
		"-test",
		"-config",
		path,
	).CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"xray config validation failed: %w: %s",
			err,
			string(output),
		)
	}

	return nil
}

func (d *Driver) Activate(
	version string,
) error {

	if !d.Installed(version) {
		return fmt.Errorf(
			"xray %s is not installed",
			version,
		)
	}

	newLink := d.currentLink() + ".new"

	_ = os.Remove(newLink)

	if err := os.Symlink(
		d.versionDir(version),
		newLink,
	); err != nil {
		return err
	}

	if err := os.Rename(
		newLink,
		d.currentLink(),
	); err != nil {

		_ = os.Remove(
			d.currentLink(),
		)

		if err := os.Rename(
			newLink,
			d.currentLink(),
		); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) CoreType() string { return "xray" }

func (d *Driver) CurrentVersion() string {
	target, err := os.Readlink(
		d.currentLink(),
	)

	if err != nil {
		return ""
	}

	return filepath.Base(target)
}

func (d *Driver) ApplyConfig(
	config []byte,
) error {

	temp := d.configPath() + ".new"

	// Agent runs with UMask=0077. Create the candidate privately
	// first, then explicitly grant read access only to the
	// dedicated Xray runtime group.
	if err := os.WriteFile(
		temp,
		config,
		0600,
	); err != nil {
		return err
	}

	group, err := user.LookupGroup(
		"vpnplatform-xray",
	)
	if err != nil {
		_ = os.Remove(temp)

		return fmt.Errorf(
			"lookup vpnplatform-xray group: %w",
			err,
		)
	}

	gid, err := strconv.Atoi(
		group.Gid,
	)
	if err != nil {
		_ = os.Remove(temp)

		return fmt.Errorf(
			"parse vpnplatform-xray gid: %w",
			err,
		)
	}

	if err := os.Chown(
		temp,
		0,
		gid,
	); err != nil {
		_ = os.Remove(temp)
		return err
	}

	if err := os.Chmod(
		temp,
		0640,
	); err != nil {
		_ = os.Remove(temp)
		return err
	}

	if err := os.Rename(
		temp,
		d.configPath(),
	); err != nil {
		_ = os.Remove(temp)
		return err
	}

	return nil
}

func systemctl(args ...string) error {
	output, err := exec.Command(
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

func (d *Driver) Stop() error {
	if d.BeforeStop != nil {
		d.BeforeStop(context.Background())
	}
	output, err := exec.Command(
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

	return nil
}

func (d *Driver) Start() error {
	if err := systemctl(
		"enable",
		"vpn-platform-xray.service",
	); err != nil {
		return err
	}

	if err := systemctl(
		"start",
		"vpn-platform-xray.service",
	); err != nil {
		return err
	}

	time.Sleep(time.Second)

	healthy, err := d.Health()

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

func (d *Driver) Restart() error {
	if err := systemctl(
		"enable",
		"vpn-platform-xray.service",
	); err != nil {
		return err
	}

	if d.BeforeStop != nil {
		d.BeforeStop(context.Background())
	}
	if err := systemctl(
		"restart",
		"vpn-platform-xray.service",
	); err != nil {
		return err
	}

	time.Sleep(time.Second)

	healthy, err := d.Health()

	if err != nil {
		return err
	}

	if !healthy {
		return fmt.Errorf(
			"xray failed health check",
		)
	}

	return nil
}

func (d *Driver) Health() (bool, error) {
	if err := d.CheckAccessFence(); err != nil {
		return false, err
	}
	if d.CurrentVersion() == "" {
		return false, nil
	}

	err := exec.Command(
		"systemctl",
		"is-active",
		"--quiet",
		"vpn-platform-xray.service",
	).Run()

	if err != nil {
		return false, nil
	}

	return true, nil
}

func (d *Driver) Snapshot() (
	string,
	error,
) {

	id := fmt.Sprintf(
		"%d",
		time.Now().UnixNano(),
	)

	dir := filepath.Join(
		d.snapshotDir(),
		id,
	)

	if err := os.MkdirAll(
		dir,
		0700,
	); err != nil {
		return "", err
	}

	meta := snapshotMetadata{
		Version: d.CurrentVersion(),
	}

	raw, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(
		filepath.Join(
			dir,
			"metadata.json",
		),
		raw,
		0600,
	); err != nil {
		return "", err
	}

	if current, err := os.ReadFile(
		d.configPath(),
	); err == nil {

		if err := os.WriteFile(
			filepath.Join(
				dir,
				"config.json",
			),
			current,
			0600,
		); err != nil {
			return "", err
		}
	}

	return id, nil
}

func (d *Driver) Rollback(
	snapshot string,
) error {

	dir := filepath.Join(
		d.snapshotDir(),
		snapshot,
	)

	raw, err := os.ReadFile(
		filepath.Join(
			dir,
			"metadata.json",
		),
	)

	if err != nil {
		return err
	}

	var metadata snapshotMetadata

	if err := json.Unmarshal(
		raw,
		&metadata,
	); err != nil {
		return err
	}

	_ = d.Stop()

	config, configErr := os.ReadFile(
		filepath.Join(
			dir,
			"config.json",
		),
	)

	if configErr == nil {
		if err := d.ApplyConfig(
			config,
		); err != nil {
			return err
		}
	}

	if metadata.Version == "" {
		_ = os.Remove(
			d.currentLink(),
		)

		_ = exec.Command(
			"systemctl",
			"disable",
			"vpn-platform-xray.service",
		).Run()

		return nil
	}

	if err := d.Activate(
		metadata.Version,
	); err != nil {
		return err
	}

	return d.Start()
}

func reconcileFailure(
	original error,
	mutationStarted bool,
	rollback func() error,
) error {
	if !mutationStarted {
		return original
	}

	if rollbackErr := rollback(); rollbackErr != nil {
		return fmt.Errorf(
			"%w; rollback failed: %v",
			original,
			rollbackErr,
		)
	}

	return fmt.Errorf(
		"%w; rollback successful",
		original,
	)
}

func (d *Driver) Reconcile(
	ctx context.Context,
	state model.DesiredState,
) error {
	intent, intentErr := d.accessIntent(state)
	if intentErr != nil {
		return intentErr
	}
	priorFence, priorErr := d.readAccessFence()
	if priorErr != nil && !os.IsNotExist(priorErr) {
		return priorErr
	}
	priorConfig, readErr := os.ReadFile(d.configPath())
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	revoking := priorFence.Blocked
	if state.Core.Type != "xray" {
		return fmt.Errorf(
			"xray driver received core=%s",
			state.Core.Type,
		)
	}

	intent.ConfigSHA256 = configDigest(priorConfig)
	var snapshot string

	// mutationStarted tracks whether reconciliation has crossed
	// the live data-plane mutation boundary.
	//
	// Staging failures with unchanged authorization leave the live runtime alone.
	// Imported revocations cross this boundary before staging: an installation,
	// secret or validation failure must not keep the withdrawn access alive.
	mutationStarted := false

	fail := func(
		original error,
	) error {
		if revoking {
			intent.Blocked = true
			fenceErr := d.writeAccessFence(intent)
			recoveryCtx, cancel := rollbackContext()
			defer cancel()
			stopErr := d.StopContext(recoveryCtx)
			return fmt.Errorf("%w; access remains closed (fence=%v stop=%v)", original, fenceErr, stopErr)
		}
		if mutationStarted {
			intent.Blocked = false
			intent.ConfigSHA256 = configDigest(priorConfig)
			if err := d.writeAccessFence(intent); err != nil {
				recoveryCtx, cancel := rollbackContext()
				defer cancel()
				_ = d.StopContext(recoveryCtx)
				return fmt.Errorf("%w; access fence recovery failed", original)
			}
		}
		return reconcileFailure(
			original,
			mutationStarted,
			func() error {
				recoveryCtx, cancel :=
					rollbackContext()

				defer cancel()

				return d.RollbackContext(
					recoveryCtx,
					snapshot,
				)
			},
		)
	}

	if state.XrayProfile != nil || state.XrayCascades != nil || priorFence.Cascades {
		authorization, err := compiler.XrayAuthorizationConfig(state)
		if err != nil {
			if priorFence.Cascades {
				revoking = true
				return fail(err)
			}
			return err
		}
		if len(priorConfig) > 0 {
			removed, err := authorizationRemoved(priorConfig, authorization)
			if err != nil {
				return err
			}
			revoking = revoking || removed
		}
	}

	if revoking {
		// Persist and stop before any cancellable installation or local preflight.
		// A crash after this write cannot restart the old credentials at boot.
		intent.Blocked = true
		if err := d.writeAccessFence(intent); err != nil {
			return fail(err)
		}
		mutationStarted = true
		stopCtx, cancel := rollbackContext()
		err := d.StopContext(stopCtx)
		cancel()
		if err != nil {
			return fail(err)
		}
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	if (state.XrayProfile != nil || state.XrayCascades != nil) && !xrayprofile.CoreCompatible(state.Core) {
		return fail(xrayprofile.ErrProfile)
	}
	var err error
	snapshot, err = d.Snapshot()
	if err != nil {
		return fail(fmt.Errorf("snapshot: %w", err))
	}

	if err :=
		d.Install(
			ctx,
			state.Core,
		); err != nil {

		return fail(
			fmt.Errorf(
				"install: %w",
				err,
			),
		)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	resolvedState, _, err :=
		d.resolveRealitySecrets(
			state,
		)

	if err != nil {
		return fail(
			fmt.Errorf(
				"resolve reality secrets: %w",
				err,
			),
		)
	}

	resolvedState, err = d.resolveTLSCertificates(resolvedState)
	if err != nil {
		return fail(fmt.Errorf("resolve TLS certificates: %w", err))
	}
	resolvedState, err = d.prepareTLSRuntime(resolvedState)
	if err != nil {
		return fail(fmt.Errorf("prepare TLS runtime: %w", err))
	}

	config, err :=
		compiler.CompileXray(
			resolvedState,
		)

	if err != nil {
		return fail(
			fmt.Errorf(
				"compile: %w",
				err,
			),
		)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	if err :=
		d.Validate(
			ctx,
			state.Core.Version,
			config,
		); err != nil {
		if state.XrayProfile != nil || state.XrayCascades != nil {
			return fail(fmt.Errorf("imported Xray native validation failed"))
		}
		return fail(err)
	}
	if err := d.checkProfileDependencies(ctx, state.XrayProfile); err != nil {
		return fail(err)
	}
	if err := d.requireProfileRuntime(ctx, state); err != nil {
		return fail(err)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	// From this point onward reconciliation may mutate the
	// currently running data plane. Set the barrier BEFORE
	// StopContext: systemctl stop may partially succeed before
	// returning an error or observing cancellation.
	if len(priorConfig) > 0 {
		removed, err := authorizationRemoved(priorConfig, config)
		if err != nil {
			return fail(err)
		}
		revoking = revoking || removed
	}
	intent.ConfigSHA256 = configDigest(config)
	intent.Blocked = true
	if err := d.writeAccessFence(intent); err != nil {
		return fail(err)
	}
	mutationStarted = true

	if err :=
		d.StopContext(ctx); err != nil {

		return fail(err)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	if err :=
		d.Activate(
			state.Core.Version,
		); err != nil {

		return fail(err)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	if err :=
		d.ApplyConfig(
			config,
		); err != nil {

		return fail(err)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	intent.Blocked = false
	if err := d.writeAccessFence(intent); err != nil {
		return fail(err)
	}
	if err :=
		d.StartContext(ctx); err != nil {

		return fail(err)
	}

	if err :=
		checkContext(ctx); err != nil {

		return fail(err)
	}

	return nil
}
