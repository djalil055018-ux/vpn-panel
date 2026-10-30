//go:build linux

package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

var errProfileDependencies = errors.New("imported Xray runtime dependencies unavailable")

func (d *Driver) checkProfileDependencies(ctx context.Context, profile *model.XrayProfileSpec) error {
	if profile == nil {
		return nil
	}
	deps, err := xrayprofile.RequiredDependencies(profile)
	if err != nil {
		return err
	}
	if len(deps.UnixSockets) == 0 && len(deps.Interfaces) == 0 {
		return nil
	}
	account, err := user.Lookup("vpnplatform-xray")
	if err != nil {
		return errProfileDependencies
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errProfileDependencies
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return errProfileDependencies
	}
	groups, err := account.GroupIds()
	if err != nil {
		return errProfileDependencies
	}
	credentials := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	for _, group := range groups {
		value, e := strconv.ParseUint(group, 10, 32)
		if e != nil {
			return errProfileDependencies
		}
		credentials.Groups = append(credentials.Groups, uint32(value))
	}
	binary, err := os.Executable()
	if err != nil {
		return errProfileDependencies
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return errProfileDependencies
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, binary, "xray-profile-probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentials}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(raw)
	// No source paths or native diagnostics escape through the API/logs.
	if cmd.Run() != nil {
		return errProfileDependencies
	}
	return nil
}

// A narrow local command run as the managed Xray UID, before adoption/update.
// It does not initialize the Agent, load credentials or call the control plane.
func ProbeProfileDependencies(ctx context.Context, input io.Reader) error {
	if os.Geteuid() == 0 {
		return errProfileDependencies
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return errProfileDependencies
	}
	var profile model.XrayProfileSpec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&profile) != nil || decoder.Decode(new(any)) != io.EOF {
		return errProfileDependencies
	}
	deps, err := xrayprofile.RequiredDependencies(&profile)
	if err != nil {
		return errProfileDependencies
	}
	for _, name := range deps.UnixSockets {
		info, err := os.Stat(name)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return errProfileDependencies
		}
		connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", name)
		if err != nil {
			return errProfileDependencies
		}
		connection.Close()
	}
	for _, name := range deps.Interfaces {
		if ctx.Err() != nil {
			return errProfileDependencies
		}
		iface, err := net.InterfaceByName(name)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return errProfileDependencies
		}
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return errProfileDependencies
		}
		err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
		syscall.Close(fd)
		if err != nil {
			return errProfileDependencies
		}
	}
	return ctx.Err()
}
