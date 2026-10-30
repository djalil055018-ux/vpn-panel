//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Serialize sequence reservation, sampling and durable enqueue across the agent
// and the systemd stop helper. The outbox's own file lock protects individual
// writes, but by itself cannot prevent sequence N+1 being queued before N.
func lockTrafficCapture(ctx context.Context, directory string) (func(), error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	path := filepath.Join(filepath.Dir(directory), "traffic-capture.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, ErrTrafficOutboxCorrupt
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, ErrTrafficOutboxCorrupt
	}
	for {
		if ctx.Err() != nil {
			file.Close()
			return nil, ctx.Err()
		}
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
