//go:build linux

package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var ErrRuntimeSelection = errors.New("node runtime selection unavailable, incompatible or conflicting")

const HysteriaMinimumAgent = "0.2.24"
const XrayProfileMinimumAgent = "0.2.31"
const XrayCascadeMinimumAgent = "0.2.34"
const selectionFile = "runtime-selection.json"

type RuntimeSelection struct {
	Format       int    `json:"format"`
	Core         string `json:"core"`
	MinimumAgent string `json:"minimum_agent"`
}

func privateOwner(info os.FileInfo) bool {
	value, ok := info.Sys().(*syscall.Stat_t)
	return ok && value.Uid == 0
}
func version(value string) ([3]int, error) {
	var result [3]int
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return result, ErrRuntimeSelection
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || strconv.Itoa(n) != part {
			return result, ErrRuntimeSelection
		}
		result[i] = n
	}
	return result, nil
}
func compatible(actual, minimum string) bool {
	a, err := version(actual)
	if err != nil {
		return false
	}
	b, err := version(minimum)
	if err != nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}
func selection(core string) (RuntimeSelection, error) {
	switch core {
	case "xray":
		return RuntimeSelection{1, core, "0.2.23"}, nil
	case "hysteria2":
		return RuntimeSelection{1, core, HysteriaMinimumAgent}, nil
	case "wireguard":
		return RuntimeSelection{1, core, "0.2.28"}, nil
	case "amneziawg":
		return RuntimeSelection{1, core, "0.2.42"}, nil
	case "pptp":
		return RuntimeSelection{1, core, "0.2.30"}, nil
	case "openvpn":
		return RuntimeSelection{1, core, "0.2.27"}, nil
	default:
		return RuntimeSelection{}, ErrRuntimeSelection
	}
}
func validateBase(base string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(base) || filepath.Clean(base) != base || base == "/" {
		return ErrRuntimeSelection
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || !privateOwner(info) {
		return ErrRuntimeSelection
	}
	return nil
}
func readSelection(base string) (RuntimeSelection, bool, error) {
	var empty RuntimeSelection
	if err := validateBase(base); err != nil {
		return empty, false, err
	}
	path := filepath.Join(base, selectionFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return empty, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !privateOwner(info) || info.Size() > 1024 {
		return empty, false, ErrRuntimeSelection
	}
	file, err := os.Open(path)
	if err != nil {
		return empty, false, ErrRuntimeSelection
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1025))
	decoder.DisallowUnknownFields()
	var record RuntimeSelection
	if decoder.Decode(&record) != nil {
		return empty, false, ErrRuntimeSelection
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return empty, false, ErrRuntimeSelection
	}
	expected, err := selection(record.Core)
	if record.Core == "xray" && (record.MinimumAgent == XrayProfileMinimumAgent || record.MinimumAgent == XrayCascadeMinimumAgent) {
		expected.MinimumAgent = record.MinimumAgent
	}
	if err != nil || record != expected {
		return empty, false, ErrRuntimeSelection
	}
	return record, true, nil
}
func pathPresent(base string, parts ...string) (bool, error) {
	path := base
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, ErrRuntimeSelection
		}
		if i < len(parts)-1 && (!info.IsDir() || !privateOwner(info) || info.Mode().Perm()&0022 != 0) {
			return false, ErrRuntimeSelection
		}
	}
	return true, nil
}
func inferredCore(base string) (string, error) {
	for _, parts := range [][]string{{"amneziawg"}, {"cores", "amneziawg"}} {
		if present, err := pathPresent(base, parts...); err != nil || present {
			return "", ErrRuntimeSelection
		}
	}
	pptp, err := pathPresent(base, "pptp")
	if err != nil || pptp {
		return "", ErrRuntimeSelection
	}
	pptpBinary, err := pathPresent(base, "cores", "pptp")
	if err != nil || pptpBinary {
		return "", ErrRuntimeSelection
	}
	native, err := pathPresent(base, "wireguard")
	if err != nil || native {
		return "", ErrRuntimeSelection
	}
	openvpn, err := pathPresent(base, "openvpn")
	if err != nil || openvpn {
		return "", ErrRuntimeSelection
	}
	hysteria, err := pathPresent(base, "hysteria2")
	if err != nil {
		return "", err
	}
	hysteriaBinary, err := pathPresent(base, "cores", "hysteria2")
	if err != nil {
		return "", err
	}
	xray, err := pathPresent(base, "xray")
	if err != nil {
		return "", err
	}
	xrayBinary, err := pathPresent(base, "cores", "xray")
	if err != nil {
		return "", err
	}
	// An unfinished Hysteria preparation also requires explicit recovery. Never
	// reinterpret its missing selection marker as permission to initialize Xray.
	if hysteria || hysteriaBinary {
		return "", ErrRuntimeSelection
	}
	if xray || xrayBinary {
		return "xray", nil
	}
	return "", nil
}

// ReadRuntimeSelection is read-only. With no requested core, an existing marker
// determines the core; only a fresh or legacy Xray node defaults to Xray. A
// requested change to an existing selection is always rejected. Migration to a
// different core needs a separately designed drain/revoke workflow.
func ReadRuntimeSelection(base, requested, agentVersion string) (RuntimeSelection, error) {
	record, exists, err := readSelection(base)
	if err != nil {
		return RuntimeSelection{}, err
	}
	if exists {
		var conflicts bool
		for _, other := range []string{"xray", "hysteria2", "openvpn", "wireguard", "pptp", "amneziawg"} {
			if other == record.Core {
				continue
			}
			present, probeErr := pathPresent(base, other)
			if probeErr != nil {
				return RuntimeSelection{}, probeErr
			}
			binary, probeErr := pathPresent(base, "cores", other)
			if probeErr != nil {
				return RuntimeSelection{}, probeErr
			}
			conflicts = conflicts || present || binary
		}
		if conflicts {
			return RuntimeSelection{}, ErrRuntimeSelection
		}
		if requested != "" && requested != record.Core || !compatible(agentVersion, record.MinimumAgent) {
			return RuntimeSelection{}, ErrRuntimeSelection
		}
		return record, nil
	}
	legacy, err := inferredCore(base)
	if err != nil {
		return RuntimeSelection{}, err
	}
	if requested == "" {
		requested = "xray"
	}
	if legacy != "" && legacy != requested {
		return RuntimeSelection{}, ErrRuntimeSelection
	}
	record, err = selection(requested)
	if err != nil || !compatible(agentVersion, record.MinimumAgent) {
		return RuntimeSelection{}, ErrRuntimeSelection
	}
	return record, nil
}

// SelectRuntimeCore publishes an immutable marker before runtime initialization.
// A backup/rollback must preserve this marker and the current access checkpoints.
// Hard-link publication prevents concurrent callers from overwriting a winner.
// This function is not yet invoked by the production agent or installer.
func SelectRuntimeCore(ctx context.Context, base, requested, agentVersion string) (RuntimeSelection, error) {
	var empty RuntimeSelection
	if ctx.Err() != nil {
		return empty, ctx.Err()
	}
	chosen, err := ReadRuntimeSelection(base, requested, agentVersion)
	if err != nil {
		return empty, err
	}
	if _, exists, err := readSelection(base); err != nil {
		return empty, err
	} else if exists {
		return ReadRuntimeSelection(base, requested, agentVersion)
	}
	raw, err := json.Marshal(chosen)
	if err != nil {
		return empty, ErrRuntimeSelection
	}
	file, err := os.CreateTemp(base, ".runtime-selection-")
	if err != nil {
		return empty, ErrRuntimeSelection
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return empty, ErrRuntimeSelection
	}
	if ctx.Err() != nil {
		return empty, ctx.Err()
	}
	if err = os.Link(file.Name(), filepath.Join(base, selectionFile)); err != nil && !os.IsExist(err) {
		return empty, ErrRuntimeSelection
	}
	directory, err := os.Open(base)
	if err != nil {
		return empty, ErrRuntimeSelection
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return empty, ErrRuntimeSelection
	}
	// Even an implicit first selection must not silently adopt a competing core.
	return ReadRuntimeSelection(base, chosen.Core, agentVersion)
}

// RequireXrayProfileRuntime raises the durable compatibility floor before an
// imported profile can start. The caller holds node ownership. Older Agents and
// installers reject this marker, and normal selection never lowers it again.
func RequireXrayProfileRuntime(ctx context.Context, base string) error {
	return requireXrayRuntime(ctx, base, XrayProfileMinimumAgent)
}

// RequireXrayCascadeRuntime prevents a legacy agent from ignoring cascade intent.
func RequireXrayCascadeRuntime(ctx context.Context, base string) error {
	return requireXrayRuntime(ctx, base, XrayCascadeMinimumAgent)
}

func requireXrayRuntime(ctx context.Context, base, minimum string) error {
	chosen, err := SelectRuntimeCore(ctx, base, "xray", XrayCascadeMinimumAgent)
	if err != nil {
		return err
	}
	if compatible(chosen.MinimumAgent, minimum) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	required := RuntimeSelection{1, "xray", minimum}
	raw, err := json.Marshal(required)
	if err != nil {
		return ErrRuntimeSelection
	}
	file, err := os.CreateTemp(base, ".runtime-profile-floor-")
	if err != nil {
		return ErrRuntimeSelection
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return ErrRuntimeSelection
	}
	current, exists, err := readSelection(base)
	if err != nil || !exists || current.Core != "xray" {
		return ErrRuntimeSelection
	}
	if compatible(current.MinimumAgent, minimum) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = os.Rename(file.Name(), filepath.Join(base, selectionFile)); err != nil {
		return ErrRuntimeSelection
	}
	directory, err := os.Open(base)
	if err != nil {
		return ErrRuntimeSelection
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrRuntimeSelection
	}
	_, err = ReadRuntimeSelection(base, "xray", XrayCascadeMinimumAgent)
	return err
}
