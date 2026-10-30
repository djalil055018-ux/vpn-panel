//go:build linux

package hysteria

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

var ErrPreflight = errors.New("Hysteria staged runtime validation failed")

// Validate starts only a verified pinned binary, under the managed unprivileged
// identity, with a copy of the candidate config on independent loopback ports.
// Its private authorizer denies all clients. No live unit, pointer, config or
// access checkpoint is changed. The child must be reaped before success returns.
func (i *Installer) Validate(parent context.Context, state model.DesiredState, uid, gid int) (result error) {
	if uid <= 0 || gid <= 0 || uint64(uid) > math.MaxInt32 || uint64(gid) > math.MaxInt32 || os.Geteuid() != 0 || parent.Err() != nil {
		return ErrPreflight
	}
	binary, err := i.destination(state.Core)
	if err != nil || i.verify(parent, binary) != nil {
		return ErrPreflight
	}
	if len(state.Services) > 1 {
		return ErrPreflight
	}
	if len(state.Services) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	authListener, err := validationTCP(state.Services[0].Port)
	if err != nil {
		return ErrPreflight
	}
	authPort := authListener.Addr().(*net.TCPAddr).Port
	authServer := &http.Server{Handler: &Authorizer{}, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
	authDone := make(chan struct{})
	go func() { _ = authServer.Serve(authListener); close(authDone) }()
	defer func() { _ = authServer.Close(); <-authDone }()
	statisticsListener, err := validationTCP(state.Services[0].Port)
	if err != nil {
		return ErrPreflight
	}
	statisticsPort := statisticsListener.Addr().(*net.TCPAddr).Port
	// Keep both TCP reservations open while selecting a distinct UDP port.
	var udpPort int
	for attempt := 0; attempt < 10; attempt++ {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			statisticsListener.Close()
			return ErrPreflight
		}
		udpPort = udp.LocalAddr().(*net.UDPAddr).Port
		_ = udp.Close()
		if udpPort != authPort && udpPort != statisticsPort {
			break
		}
		udpPort = 0
	}
	_ = statisticsListener.Close()
	if udpPort == 0 {
		return ErrPreflight
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return ErrPreflight
	}
	options := compiler.HysteriaRuntimeOptions{AuthPort: authPort, StatisticsPort: statisticsPort, StatisticsSecret: hex.EncodeToString(secret)}
	if _, err := compiler.CompileHysteria(state, options); err != nil {
		return ErrPreflight
	}
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	state.Services[0].Listen = "127.0.0.1"
	state.Services[0].Port = udpPort
	config, err := compiler.CompileHysteria(state, options)
	if err != nil {
		return ErrPreflight
	}
	runtimeRoot := filepath.Join(i.base, "hysteria2")
	if runtimeTLSDirectory(runtimeRoot, gid) != nil {
		return ErrPreflight
	}
	temp, err := os.MkdirTemp(runtimeRoot, ".preflight-")
	if err != nil {
		return ErrPreflight
	}
	defer os.RemoveAll(temp)
	if os.Chown(temp, 0, gid) != nil || os.Chmod(temp, 0750) != nil {
		return ErrPreflight
	}
	configPath := filepath.Join(temp, "config.json")
	if writeRuntimeTLS(configPath, config, gid) != nil {
		return ErrPreflight
	}
	if ctx.Err() != nil {
		return ErrPreflight
	}
	command := exec.Command(binary, "server", "-c", configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}, Pdeathsig: syscall.SIGKILL}
	if command.Start() != nil {
		return ErrPreflight
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	defer func() {
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			result = errors.Join(ErrPreflight, ErrRuntimeStop)
		}
	}()
	statistics, err := NewStatistics(statisticsPort, options.StatisticsSecret)
	if err != nil {
		return ErrPreflight
	}
	for {
		select {
		case <-ctx.Done():
			return ErrPreflight
		case <-done:
			return ErrPreflight
		default:
		}
		if _, err := statistics.Traffic(ctx); err == nil {
			// The stats listener can open before a later native startup error. A
			// second check and live-child observation avoid accepting that window.
			select {
			case <-ctx.Done():
				return ErrPreflight
			case <-done:
				return ErrPreflight
			case <-time.After(250 * time.Millisecond):
			}
			if _, err = statistics.Traffic(ctx); err == nil {
				select {
				case <-done:
					return ErrPreflight
				default:
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ErrPreflight
		case <-done:
			return ErrPreflight
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func validationTCP(excluded int) (net.Listener, error) {
	for attempt := 0; attempt < 10; attempt++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, ErrPreflight
		}
		if listener.Addr().(*net.TCPAddr).Port != excluded {
			return listener, nil
		}
		_ = listener.Close()
	}
	return nil, ErrPreflight
}
