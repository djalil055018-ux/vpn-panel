package hysteria

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const runningServiceFixture = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nControlPID=0\nInvocationID=11111111111111111111111111111111\nJob=\nKillMode=control-group\nSendSIGKILL=yes\nFinalKillSignal=9\n"

func TestCaptureInvocationOnlyAcceptsLiveExecStop(t *testing.T) {
	stats, _ := NewStatistics(12345, strings.Repeat("s", 32))
	runtime, _ := NewSystemdRuntime(ManagedService, stats)
	stopping := strings.NewReplacer("ActiveState=active", "ActiveState=deactivating", "SubState=running", "SubState=stop", "ControlPID=0", "ControlPID=456", "Job=", "Job=77").Replace(runningServiceFixture)
	runtime.run = func(context.Context, ...string) ([]byte, error) { return []byte(stopping), nil }
	if epoch, err := runtime.CaptureInvocation(context.Background()); err != nil || epoch != strings.Repeat("1", 32) {
		t.Fatal("live stop helper invocation rejected")
	}
	if _, err := runtime.Invocation(context.Background()); err == nil {
		t.Fatal("stopping runtime marked healthy")
	}
	for _, change := range [][2]string{{"MainPID=123", "MainPID=0"}, {"SubState=stop", "SubState=stop-sigterm"}, {"ActiveState=deactivating", "ActiveState=failed"}, {strings.Repeat("1", 32), strings.Repeat("0", 32)}} {
		raw := strings.Replace(stopping, change[0], change[1], 1)
		runtime.run = func(context.Context, ...string) ([]byte, error) { return []byte(raw), nil }
		if _, err := runtime.CaptureInvocation(context.Background()); err == nil {
			t.Fatal("dead/unstable stop invocation accepted")
		}
	}
}

func TestManagedServiceStateRejectsUnsafeAndIncompleteUnits(t *testing.T) {
	s, err := parseServiceState([]byte(runningServiceFixture))
	if err != nil || !s.running() || s.stopped() {
		t.Fatal("valid running state rejected")
	}
	for _, replacement := range [][2]string{{"KillMode=control-group", "KillMode=process"}, {"SendSIGKILL=yes", "SendSIGKILL=no"}, {"LoadState=loaded", "LoadState=not-found"}, {"FinalKillSignal=9", "FinalKillSignal=15"}, {"MainPID=123", "MainPID=-1"}, {"ControlPID=0", "ControlPID=broken"}} {
		if _, err := parseServiceState([]byte(strings.ReplaceAll(runningServiceFixture, replacement[0], replacement[1]))); err == nil {
			t.Fatal("unsafe state accepted", replacement[0])
		}
	}
	for _, raw := range []string{"", runningServiceFixture + "MainPID=123\n", strings.ReplaceAll(runningServiceFixture, "ControlPID=0\n", ""), strings.Repeat("x", 8193)} {
		if _, err := parseServiceState([]byte(raw)); err == nil {
			t.Fatal("malformed state accepted")
		}
	}
	for _, replacement := range [][2]string{{"Job=", "Job=9"}, {"MainPID=123", "MainPID=0"}, {"ControlPID=0", "ControlPID=124"}, {"SubState=running", "SubState=auto-restart"}, {"InvocationID=11111111111111111111111111111111", "InvocationID=00000000000000000000000000000000"}} {
		s, err := parseServiceState([]byte(strings.ReplaceAll(runningServiceFixture, replacement[0], replacement[1])))
		if err == nil && s.running() {
			t.Fatal("unstable invocation accepted", replacement[0])
		}
	}
}
func TestManagedServiceConstructorRejectsOtherServices(t *testing.T) {
	s, _ := NewStatistics(12345, strings.Repeat("s", 32))
	for _, unit := range []string{"sshd.service", "vpn-platform-xray.service", "--help", ManagedService + "\n", "vpn-platform-hysteria-candidate-xyz.service"} {
		if _, err := NewSystemdRuntime(unit, s); err == nil {
			t.Fatal("unrelated unit accepted")
		}
	}
	for _, unit := range []string{ManagedService, "vpn-platform-hysteria-candidate-0123456789abcdef.service"} {
		if _, err := NewSystemdRuntime(unit, s); err != nil {
			t.Fatal(err)
		}
	}
}
func TestManagedServiceStopRequiresZeroProcessesAndNoJobs(t *testing.T) {
	s, _ := NewStatistics(12345, strings.Repeat("s", 32))
	r, _ := NewSystemdRuntime(ManagedService, s)
	stopped := strings.NewReplacer("ActiveState=active", "ActiveState=inactive", "SubState=running", "SubState=dead", "MainPID=123", "MainPID=0").Replace(runningServiceFixture)
	for _, raw := range []string{runningServiceFixture, strings.Replace(stopped, "ControlPID=0", "ControlPID=20", 1), strings.Replace(stopped, "Job=", "Job=88", 1)} {
		r.run = func(context.Context, ...string) ([]byte, error) { return []byte(raw), nil }
		if err := r.Stop(context.Background()); !errors.Is(err, ErrRuntimeStop) {
			t.Fatal("unconfirmed stop accepted")
		}
	}
	var calls [][]string
	r.run = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		return []byte(stopped), nil
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !reflect.DeepEqual(calls[0], []string{"stop", ManagedService}) || calls[1][0] != "show" {
		t.Fatal("stop did not verify fixed unit")
	}
}
func TestManagedServiceStartChecksKillPolicyBeforeMutation(t *testing.T) {
	s, _ := NewStatistics(12345, strings.Repeat("s", 32))
	r, _ := NewSystemdRuntime(ManagedService, s)
	calls := 0
	r.run = func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if args[0] != "show" {
			t.Fatal("unsafe unit started")
		}
		return []byte(strings.Replace(runningServiceFixture, "KillMode=control-group", "KillMode=none", 1)), nil
	}
	if err := r.Start(context.Background()); err == nil || calls != 1 {
		t.Fatal("unsafe unit accepted")
	}
}
func TestManagedServiceReadinessRejectsEpochChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer server.Close()
	s := &Statistics{base: server.URL, secret: strings.Repeat("s", 32), http: server.Client()}
	r, _ := NewSystemdRuntime(ManagedService, s)
	calls := 0
	r.run = func(context.Context, ...string) ([]byte, error) {
		calls++
		if calls%2 == 0 {
			return []byte(strings.Replace(runningServiceFixture, strings.Repeat("1", 32), strings.Repeat("2", 32), 1)), nil
		}
		return []byte(runningServiceFixture), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := r.Ready(ctx); err == nil {
		t.Fatal("mixed invocation readiness accepted")
	}
	r.run = func(context.Context, ...string) ([]byte, error) { return []byte(runningServiceFixture), nil }
	if err := r.Ready(context.Background()); err != nil {
		t.Fatal("consistent healthy invocation rejected")
	}
}
