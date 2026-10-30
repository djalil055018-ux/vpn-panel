//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"sync"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/core/hysteria"
	"vpn-platform/internal/core/openvpn"
	"vpn-platform/internal/core/pptp"
	"vpn-platform/internal/core/wireguard"
	"vpn-platform/internal/core/xray"
	"vpn-platform/internal/model"
)

var errSelectedRuntime = errors.New("selected node runtime unavailable or requires repair")

type agentRuntime struct {
	driver  leaseRuntimeDriver
	traffic *agent.TrafficWorker
	refresh certificateRuntimeRefresher
	close   func() error
}

// The caller holds node lifecycle ownership before registration and keeps it
// through this runtime's Close. Hysteria creation belongs to guarded provisioning.
func openAgentRuntime(ctx context.Context, coreType, base, statePath string, state agent.LocalState, client *agent.Client) (*agentRuntime, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !model.ValidRuntimeCore(coreType) {
		return nil, errSelectedRuntime
	}
	if coreType != "xray" && statePath != filepath.Join(base, "agent", "state.json") {
		return nil, errSelectedRuntime
	}
	outbox, err := agent.NewTrafficOutbox(filepath.Join(filepath.Dir(statePath), "traffic-outbox"), state.NodeID)
	if coreType == "xray" {
		driver := xray.New(base)
		if initErr := driver.Init(); initErr != nil {
			return nil, initErr
		}
		result := &agentRuntime{driver: driver, refresh: xrayCertificateRefresher(driver), close: func() error { return nil }}
		if err != nil {
			log.Print("traffic delivery status=queue_requires_repair")
			return result, nil
		}
		result.traffic = agent.NewTrafficWorker(outbox, client, state.AgentToken, log.Printf)
		driver.BeforeStop = result.traffic.BeforeStop
		return result, nil
	}
	if err != nil {
		return nil, errSelectedRuntime
	}
	if coreType == "wireguard" || coreType == "amneziawg" {
		open := wireguard.Open
		if coreType == "amneziawg" {
			open = wireguard.OpenAmneziaWG
		}
		driver, err := open(ctx, base)
		if err != nil {
			return nil, err
		}
		collector := agent.NewWireGuardTrafficCollector(driver, filepath.Join(filepath.Dir(statePath), "traffic-sequence"))
		traffic, err := agent.NewTrafficWorkerWithCollector(outbox, client, state.AgentToken, log.Printf, collector)
		if err != nil {
			driver.Close()
			return nil, err
		}
		driver.BeforeStop = traffic.BeforeStop
		return &agentRuntime{driver: driver, traffic: traffic, close: driver.Close}, nil
	}
	if coreType == "pptp" {
		driver, err := pptp.Open(ctx, base)
		if err != nil {
			return nil, err
		}
		collector := agent.NewPPTPTrafficCollector(driver, filepath.Join(filepath.Dir(statePath), "traffic-sequence"))
		traffic, err := agent.NewTrafficWorkerWithCollector(outbox, client, state.AgentToken, log.Printf, collector)
		if err != nil {
			driver.Close()
			return nil, err
		}
		driver.BeforeStop = traffic.BeforeStop
		return &agentRuntime{driver: driver, traffic: traffic, close: driver.Close}, nil
	}
	if coreType == "openvpn" {
		driver, err := openvpn.Open(ctx, base)
		if err != nil {
			return nil, err
		}
		collector := agent.NewOpenVPNTrafficCollector(driver, filepath.Join(filepath.Dir(statePath), "traffic-sequence"))
		traffic, err := agent.NewTrafficWorkerWithCollector(outbox, client, state.AgentToken, log.Printf, collector)
		if err != nil {
			return nil, err
		}
		driver.BeforeStop = traffic.BeforeStop
		return &agentRuntime{driver: driver, traffic: traffic, close: driver.Close}, nil
	}
	identity, err := hysteria.ReadManagedAccount(ctx)
	if err != nil {
		return nil, err
	}
	if err = hysteria.VerifyManagedRuntime(ctx, base, identity); err != nil {
		return nil, err
	}
	stats, invocation, err := hysteria.PrepareTrafficSource(base, identity, hysteria.ManagedService)
	if err != nil {
		return nil, err
	}
	collector, err := agent.NewHysteriaTrafficCollector(stats, filepath.Join(filepath.Dir(statePath), "traffic-sequence"), invocation)
	if err != nil {
		return nil, err
	}
	traffic, err := agent.NewTrafficWorkerWithCollector(outbox, client, state.AgentToken, log.Printf, collector.Collect)
	if err != nil {
		return nil, err
	}
	driver, err := hysteria.OpenPendingManagedDriver(ctx, base, identity.UID, identity.GID, hysteria.ManagedService, traffic.BeforeStop)
	if err != nil {
		return nil, err
	}
	pending := &pendingHysteriaRuntime{Driver: driver, pending: true}
	return &agentRuntime{driver: pending, traffic: traffic, refresh: pending.refreshCertificate, close: driver.Close}, nil
}

type pendingHysteriaRuntime struct {
	*hysteria.Driver
	mutex   sync.Mutex
	pending bool
}

func (d *pendingHysteriaRuntime) Reconcile(ctx context.Context, state model.DesiredState) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// An invalid/cancelled attempt must not unlock certificate-driven startup.
	// A successful apply or an actually healthy leased rollback ends bootstrap.
	err := d.Driver.Reconcile(ctx, state)
	if err == nil {
		d.pending = false
	} else if ctx.Err() == nil {
		if healthy, _ := d.Driver.Health(); healthy {
			d.pending = false
		}
	}
	return err
}
func (d *pendingHysteriaRuntime) RestoreTerminalAssignment(ctx context.Context, assignment model.AgentAssignment) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if healthyHysteriaAssignment(assignment) {
		if d.pending {
			if err := d.Driver.RestoreHealthyDesired(ctx, assignment.DesiredState); err != nil {
				return err
			}
		} else if err := d.Driver.ConfirmHealthyDesired(ctx, assignment.DesiredState); err != nil {
			return err
		}
	} else if assignment.DeploymentStatus == "rolled_back" || assignment.DeploymentStatus == "failed" {
		if assignment.FenceRequest != nil || assignment.NodeAppliedGeneration <= 0 || assignment.DesiredState.Generation <= assignment.NodeAppliedGeneration || assignment.DesiredState.Core.Type != "hysteria2" {
			return errSelectedRuntime
		}
		if !d.pending {
			return nil
		}
		if err := d.Driver.RestoreRolledBackAssignment(ctx, assignment); err != nil {
			return err
		}
	} else {
		return errSelectedRuntime
	}
	d.pending = false
	return nil
}

func healthyHysteriaAssignment(assignment model.AgentAssignment) bool {
	version := assignment.DesiredState.Core.Version
	if len(assignment.DesiredState.Services) == 0 {
		version = ""
	}
	return assignment.DeploymentStatus == "healthy" && assignment.FenceRequest == nil && assignment.DesiredState.Generation > 0 && assignment.DesiredState.Core.Type == "hysteria2" && assignment.NodeAppliedGeneration == assignment.DesiredState.Generation && assignment.AppliedCoreVersion == version
}
func (d *pendingHysteriaRuntime) refreshCertificate(ctx context.Context, id, domain string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.pending {
		return errSelectedRuntime
	}
	return d.Driver.RefreshTLSCertificateContext(ctx, id, domain)
}
