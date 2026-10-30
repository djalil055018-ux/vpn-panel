package hysteria

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ManagedService = "vpn-platform-hysteria.service"

var managedUnitName = regexp.MustCompile(`^vpn-platform-hysteria(?:-candidate-[0-9a-f]{16})?\.service$`)
var invocationIdentity = regexp.MustCompile(`^[0-9a-f]{32}$`)
var ErrSystemdRuntime = errors.New("Hysteria managed service unavailable or inconsistent")

// SystemdRuntime controls a preinstalled Hysteria unit, never arbitrary services.
// Candidate names allow isolated real-systemd verification without addressing
// the production unit. Unit installation/configuration belongs to the driver.
type SystemdRuntime struct {
	unit       string
	statistics *Statistics
	run        func(context.Context, ...string) ([]byte, error)
}

func NewSystemdRuntime(unit string, statistics *Statistics) (*SystemdRuntime, error) {
	if !managedUnitName.MatchString(unit) || statistics == nil {
		return nil, ErrSystemdRuntime
	}
	return &SystemdRuntime{unit: unit, statistics: statistics, run: func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "systemctl", args...).Output()
	}}, nil
}

type serviceState struct {
	active, sub, invocation, job string
	mainPID, controlPID          int64
}

func parseServiceState(raw []byte) (serviceState, error) {
	var state serviceState
	if len(raw) > 8192 {
		return state, ErrSystemdRuntime
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return state, ErrSystemdRuntime
		}
		if _, exists := values[key]; exists {
			return state, ErrSystemdRuntime
		}
		values[key] = value
	}
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "MainPID", "ControlPID", "InvocationID", "Job", "KillMode", "SendSIGKILL", "FinalKillSignal"} {
		if _, ok := values[key]; !ok {
			return state, ErrSystemdRuntime
		}
	}
	// A unit configured to leave child processes alive cannot prove revocation.
	if values["LoadState"] != "loaded" || values["KillMode"] != "control-group" || values["SendSIGKILL"] != "yes" || values["FinalKillSignal"] != "9" {
		return state, ErrSystemdRuntime
	}
	var err error
	state.mainPID, err = strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || state.mainPID < 0 {
		return state, ErrSystemdRuntime
	}
	state.controlPID, err = strconv.ParseInt(values["ControlPID"], 10, 32)
	if err != nil || state.controlPID < 0 {
		return state, ErrSystemdRuntime
	}
	state.active = values["ActiveState"]
	state.sub = values["SubState"]
	state.invocation = values["InvocationID"]
	state.job = values["Job"]
	return state, nil
}

func (r *SystemdRuntime) state(ctx context.Context) (serviceState, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := r.run(ctx, "show", r.unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Job,KillMode,SendSIGKILL,FinalKillSignal", "--no-pager")
	if err != nil {
		return serviceState{}, ErrSystemdRuntime
	}
	return parseServiceState(raw)
}

func (s serviceState) running() bool {
	return s.active == "active" && s.sub == "running" && s.mainPID > 0 && s.controlPID == 0 && s.job == "" && invocationIdentity.MatchString(s.invocation) && s.invocation != strings.Repeat("0", 32)
}
func (s serviceState) stopped() bool {
	return ((s.active == "inactive" && s.sub == "dead") || (s.active == "failed" && s.sub == "failed")) && s.mainPID == 0 && s.controlPID == 0 && s.job == ""
}

// Invocation supplies the traffic collector with the identity of the core
// process invocation. An agent restart alone must not create a new traffic epoch.
func (r *SystemdRuntime) Invocation(ctx context.Context) (string, error) {
	s, err := r.state(ctx)
	if err != nil || !s.running() {
		return "", ErrSystemdRuntime
	}
	return s.invocation, nil
}

func (r *SystemdRuntime) Stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if _, err := r.run(ctx, "stop", r.unit); err != nil {
		return ErrRuntimeStop
	}
	s, err := r.state(ctx)
	if err != nil || !s.stopped() {
		return ErrRuntimeStop
	}
	return nil
}

// CaptureInvocation also accepts the ExecStop phase, while the original core
// PID is still alive. Normal health never treats a stopping unit as ready.
func (r *SystemdRuntime) CaptureInvocation(ctx context.Context) (string, error) {
	state, err := r.state(ctx)
	if err != nil {
		return "", err
	}
	if state.running() {
		return state.invocation, nil
	}
	if state.active == "deactivating" && state.sub == "stop" && state.mainPID > 0 && invocationIdentity.MatchString(state.invocation) && state.invocation != strings.Repeat("0", 32) {
		return state.invocation, nil
	}
	return "", ErrSystemdRuntime
}

func (r *SystemdRuntime) Stopped(ctx context.Context) error {
	state, err := r.state(ctx)
	if err != nil || !state.stopped() {
		return ErrRuntimeStop
	}
	return nil
}

func (r *SystemdRuntime) Start(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// Verify the loaded unit's kill policy before starting any process.
	if _, err := r.state(ctx); err != nil {
		return err
	}
	if _, err := r.run(ctx, "start", r.unit); err != nil {
		return ErrSystemdRuntime
	}
	return nil
}

func (r *SystemdRuntime) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		before, err := r.Invocation(ctx)
		if err == nil {
			if _, err = r.statistics.Traffic(ctx); err == nil {
				after, err := r.Invocation(ctx)
				if err == nil && before == after {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ErrSystemdRuntime
		case <-time.After(100 * time.Millisecond):
		}
	}
}
