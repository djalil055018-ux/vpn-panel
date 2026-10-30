//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/core"
	"vpn-platform/internal/core/hysteria"
	"vpn-platform/internal/core/openvpn"
	"vpn-platform/internal/core/pptp"
	"vpn-platform/internal/core/wireguard"
	"vpn-platform/internal/core/xray"
)

var errLocalCommand = errors.New("local agent command failed")

// Local lifecycle commands do not initialize registration, the API client or
// leases. In particular ExecStop must work after the owner agent has died.
func runLocalCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println(agentVersion)
		return true, nil
	}
	if args[0] == "wireguard-runtime-stop" {
		return true, runWireGuardStop(args[1:])
	}
	if args[0] == "provision-runtime" {
		return true, runProvisionCommand(args[1:])
	}
	if args[0] == "xray-runtime-check" {
		if len(args) != 1 {
			return true, errLocalCommand
		}
		return true, xray.New("/var/lib/vpn-platform").CheckAccessFence()
	}
	if args[0] == "xray-profile-probe" {
		if len(args) != 1 {
			return true, errLocalCommand
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return true, xray.ProbeProfileDependencies(ctx, os.Stdin)
	}
	if args[0] == "pptp-network-start" {
		if len(args) != 1 {
			return true, errLocalCommand
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if _, err := core.ReadRuntimeSelection("/var/lib/vpn-platform", "pptp", agentVersion); err != nil {
			return true, err
		}
		return true, pptp.PrepareNetwork(ctx)
	}
	if args[0] == "pptp-runtime-start" {
		if len(args) != 2 {
			return true, errLocalCommand
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return true, pptp.StartRuntime(ctx, args[1])
	}
	if args[0] == "pptp-traffic-event" {
		if len(args) != 4 {
			return true, errLocalCommand
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return true, pptp.RecordTrafficEnvironment(ctx, args[1], args[2], args[3], os.Getenv)
	}
	if args[0] == "openvpn-network-start" {
		if len(args) != 1 {
			return true, errLocalCommand
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return true, openvpn.PrepareNetwork(ctx)
	}
	if args[0] == "openvpn-traffic-event" {
		if len(args) > 2 {
			return true, errLocalCommand
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return true, openvpn.RecordTrafficEnvironment(ctx, os.Getenv("VPN_PLATFORM_OPENVPN_DATA_DIR"), os.Getenv)
	}
	if args[0] != "capture-traffic" {
		return true, errLocalCommand
	}
	flags := flag.NewFlagSet("capture-traffic", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	base := flags.String("data-dir", "", "private node data directory")
	unit := flags.String("unit", hysteria.ManagedService, "managed core unit")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *base == "" {
		return true, errLocalCommand
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return true, captureStoredTraffic(ctx, *base, *unit)
}

func runProvisionCommand(args []string) error {
	flags := flag.NewFlagSet("provision-runtime", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	base := flags.String("data-dir", "", "node data directory")
	selected := flags.String("core", "", "explicit runtime core")
	descriptor := flags.Int("ownership-fd", -1, "inherited installer ownership descriptor")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *base == "" || (*selected != "hysteria2" && *selected != "openvpn" && *selected != "wireguard" && *selected != "pptp") {
		return errLocalCommand
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var release func()
	var err error
	if *descriptor == -1 {
		release, err = core.AcquireNodeOwnership(ctx, *base)
	} else {
		release, err = core.AdoptNodeOwnershipFD(ctx, *base, *descriptor)
	}
	if err != nil {
		return errLocalCommand
	}
	defer release()
	if *selected == "wireguard" {
		if _, err = core.SelectRuntimeCore(ctx, *base, *selected, agentVersion); err != nil {
			return err
		}
		return wireguard.Provision(ctx, *base)
	}
	if *selected == "pptp" {
		if _, err = core.SelectRuntimeCore(ctx, *base, *selected, agentVersion); err != nil {
			return err
		}
		return pptp.Provision(ctx, *base)
	}
	if *selected == "openvpn" {
		if _, err = core.SelectRuntimeCore(ctx, *base, *selected, agentVersion); err != nil {
			return err
		}
		return openvpn.Provision(ctx, *base)
	}
	if _, err = hysteria.ProvisionManagedRuntime(ctx, *base, agentVersion); err != nil {
		return errLocalCommand
	}
	return nil
}

func captureStoredTraffic(ctx context.Context, base, unit string) error {
	stats, invocation, err := hysteria.OpenStoredTrafficSource(base, unit, true)
	if err != nil {
		return errLocalCommand
	}
	directory := filepath.Join(base, "agent")
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errLocalCommand
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errLocalCommand
	}
	file, err := os.OpenFile(filepath.Join(directory, "state.json"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errLocalCommand
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<10 {
		return errLocalCommand
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errLocalCommand
	}
	// Only the node identity is decoded. Credentials are never logged or needed.
	var state struct {
		NodeID string `json:"node_id"`
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &state) != nil {
		return errLocalCommand
	}
	outbox, err := agent.NewTrafficOutbox(filepath.Join(directory, "traffic-outbox"), state.NodeID)
	if err != nil {
		return errLocalCommand
	}
	collector, err := agent.NewHysteriaTrafficCollector(stats, filepath.Join(directory, "traffic-sequence"), invocation)
	if err != nil {
		return errLocalCommand
	}
	if agent.CaptureTrafficToOutbox(ctx, outbox, collector.Collect) != nil {
		return errLocalCommand
	}
	return nil
}

// ExecStopPost uses this after the owning agent has exited. Ownership prevents
// a concurrent installer or running agent from racing interface removal.
func runWireGuardStop(args []string) error {
	flags := flag.NewFlagSet("wireguard-runtime-stop", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	base := flags.String("data-dir", "", "node directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *base == "" {
		return errLocalCommand
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	release, err := core.AcquireNodeOwnership(ctx, *base)
	if err != nil {
		return err
	}
	defer release()
	chosen, err := core.ReadRuntimeSelection(*base, "wireguard", agentVersion)
	if err != nil || chosen.Core != "wireguard" {
		return errLocalCommand
	}
	runtime, err := wireguard.OpenKernelRuntime(filepath.Join(*base, "wireguard"), wireguard.NFTNetwork{})
	if err != nil {
		return err
	}
	return runtime.Stop(ctx)
}
