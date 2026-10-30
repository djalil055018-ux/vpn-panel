//go:build linux

package wireguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type userspaceReceipt struct {
	Format       int
	PID          int
	Start        string
	Epoch        string
	SocketDevice uint64
	SocketInode  uint64
}

// The durable receipt owns a particular socket inode, never merely its name.
// A daemon killed before its normal unlink must not prevent crash recovery, or
// authorize removal of another process's replacement control socket.
func removeUserspaceSocket(saved userspaceReceipt) error {
	path := filepath.Join("/var/run/amneziawg", InterfaceName+".sock")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 || saved.SocketInode == 0 || stat.Dev != saved.SocketDevice || stat.Ino != saved.SocketInode {
		return fmt.Errorf("unowned native control socket: %w", ErrRuntime)
	}
	return os.Remove(path)
}

func processStart(pid int) (string, error) {
	raw, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil {
		return "", e
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "", ErrRuntime
	}
	fields := strings.Fields(string(raw)[end+1:])
	if len(fields) < 20 {
		return "", ErrRuntime
	}
	start := fields[19]
	if _, e = strconv.ParseUint(start, 10, 64); e != nil {
		return "", ErrRuntime
	}
	return start, nil
}

// Take a pidfd-backed process handle before checking /proc. A reused numeric
// PID must never turn a stop request into a signal to an unrelated process.
func (k *KernelRuntime) ownedUserspace(r interfaceReceipt) (*os.Process, userspaceReceipt, error) {
	var saved userspaceReceipt
	raw, e := readPrivate(filepath.Join(k.root, "process.json"), 4096)
	if e != nil {
		return nil, saved, e
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Format != 1 || saved.PID < 1 || saved.PID > 1<<30 || saved.Start == "" || saved.Epoch != r.Epoch {
		return nil, saved, ErrRuntime
	}
	p, e := os.FindProcess(saved.PID)
	if e != nil {
		return nil, saved, e
	}
	reject := func(err error) (*os.Process, userspaceReceipt, error) { p.Release(); return nil, saved, err }
	start, e := processStart(saved.PID)
	if e != nil {
		return reject(e)
	}
	if start != saved.Start {
		return reject(os.ErrNotExist)
	}
	argv, e := os.ReadFile("/proc/" + strconv.Itoa(saved.PID) + "/cmdline")
	if e != nil {
		return reject(e)
	}
	parts := strings.Split(string(argv), "\x00")
	if len(parts) != 4 || parts[0] != k.variant.binaryPath || parts[1] != "-f" || parts[2] != InterfaceName || parts[3] != "" {
		return reject(ErrRuntime)
	}
	f, e := os.Open("/proc/" + strconv.Itoa(saved.PID) + "/exe")
	if e != nil {
		return reject(e)
	}
	data, e := io.ReadAll(io.LimitReader(f, 64<<20+1))
	f.Close()
	if e != nil {
		return reject(e)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != k.variant.binarySHA {
		return reject(ErrRuntime)
	}
	return p, saved, nil
}

func (k *KernelRuntime) userspaceAlive() error {
	r, e := k.readInterface()
	if e != nil {
		return e
	}
	p, _, e := k.ownedUserspace(r)
	if e != nil {
		return ErrRuntime
	}
	defer p.Release()
	if p.Signal(syscall.Signal(0)) != nil {
		return ErrRuntime
	}
	return k.variant.verify()
}

func (k *KernelRuntime) startUserspace(ctx context.Context, r interfaceReceipt) error {
	if e := k.variant.verify(); e != nil {
		return e
	}
	control := filepath.Join("/var/run/amneziawg", InterfaceName+".sock")
	if _, e := os.Lstat(control); !os.IsNotExist(e) {
		return fmt.Errorf("native control socket is already present: %w", ErrRuntime)
	}
	if _, e := os.Lstat(filepath.Join(k.root, "process.json")); !os.IsNotExist(e) {
		return fmt.Errorf("native process receipt is already present: %w", ErrRuntime)
	}
	cmd := exec.Command(k.variant.binaryPath, "-f", InterfaceName)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = append(os.Environ(), "LOG_LEVEL=silent")
	if e := cmd.Start(); e != nil {
		return ErrRuntime
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	abort := func(e error) error {
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return e
	}
	start, e := processStart(cmd.Process.Pid)
	if e != nil {
		return abort(ErrRuntime)
	}
	saved := userspaceReceipt{Format: 1, PID: cmd.Process.Pid, Start: start, Epoch: r.Epoch}
	data, e := json.Marshal(saved)
	if e != nil {
		return abort(e)
	}
	if e = writePrivate(filepath.Join(k.root, "process.json"), data); e != nil {
		return abort(e)
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, e := net.InterfaceByName(InterfaceName); e == nil {
			if info, e := os.Lstat(control); e == nil && info.Mode()&os.ModeSocket != 0 {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
					return abort(ErrRuntime)
				}
				saved.SocketDevice, saved.SocketInode = stat.Dev, stat.Ino
				data, e := json.Marshal(saved)
				if e != nil {
					return abort(e)
				}
				if e = writePrivate(filepath.Join(k.root, "process.json"), data); e != nil {
					return abort(e)
				}
				if _, e = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "alias", "vpn-platform-wireguard-"+r.Epoch); e != nil {
					return abort(e)
				}
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return abort(ctx.Err())
		case <-deadline.C:
			return abort(fmt.Errorf("native daemon readiness deadline: %w", ErrRuntime))
		case <-done:
			return fmt.Errorf("native daemon exited before readiness: %w", ErrRuntime)
		case <-tick.C:
		}
	}
}

func (k *KernelRuntime) stopUserspace(ctx context.Context, r interfaceReceipt) error {
	p, saved, e := k.ownedUserspace(r)
	if e != nil {
		if !os.IsNotExist(e) {
			return e
		}
		if _, linkErr := net.InterfaceByName(InterfaceName); linkErr == nil {
			return ErrRuntime
		}
		// A missing process after a crash is expected only when its interface is
		// also absent. Keep the durable traffic ledger and generation receipt.
		if e = removeUserspaceSocket(saved); e != nil {
			return e
		}
		if remove := os.Remove(filepath.Join(k.root, "process.json")); remove != nil && !os.IsNotExist(remove) {
			return remove
		}
		return nil
	}
	defer p.Release()
	if e = p.Signal(syscall.SIGTERM); e != nil && !errors.Is(e, os.ErrProcessDone) {
		return ErrRuntime
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	killed := false
	for {
		start, probe := processStart(saved.PID)
		if os.IsNotExist(probe) || (probe == nil && start != saved.Start) {
			break
		}
		if probe != nil {
			return ErrRuntime
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			if killed {
				return ErrRuntime
			}
			if e = p.Kill(); e != nil && !errors.Is(e, os.ErrProcessDone) {
				return ErrRuntime
			}
			killed = true
			deadline.Reset(2 * time.Second)
		case <-tick.C:
		}
	}
	if _, e := net.InterfaceByName(InterfaceName); e == nil {
		return ErrRuntime
	}
	if e = removeUserspaceSocket(saved); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(k.root, "process.json")); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
