//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var ErrNodeOwnership = errors.New("node runtime is owned by another agent or requires repair")

// AcquireNodeOwnership excludes competing agent lifetimes and provisioning.
// Keep the lock until all workers and the runtime have stopped. The systemd
// traffic stop helper deliberately does not acquire it. Never unlink this file:
// unlinking an in-use lock could create two independent owners of one node.
func AcquireNodeOwnership(ctx context.Context, base string) (func(), error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if validateBase(base) != nil {
		return nil, ErrNodeOwnership
	}
	file, err := os.OpenFile(filepath.Join(base, "agent-lifecycle.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrNodeOwnership
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !privateOwner(info) {
		file.Close()
		return nil, ErrNodeOwnership
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, ErrNodeOwnership
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }) }
	if ctx.Err() != nil {
		release()
		return nil, ctx.Err()
	}
	return release, nil
}

// AdoptNodeOwnershipFD is for a child provisioning process launched by the node
// installer while it holds the node lock. The inherited descriptor must refer to
// the exact protected lock inode and obtain LOCK_EX. Closing the child's copy
// must NOT explicitly unlock the shared open file description held by the parent.
func AdoptNodeOwnershipFD(ctx context.Context, base string, descriptor int) (func(), error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if descriptor < 3 || validateBase(base) != nil {
		return nil, ErrNodeOwnership
	}
	file := os.NewFile(uintptr(descriptor), "inherited-node-ownership")
	if file == nil {
		return nil, ErrNodeOwnership
	}
	reject := func() (func(), error) { file.Close(); return nil, ErrNodeOwnership }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !privateOwner(info) {
		return reject()
	}
	expected, err := os.Lstat(filepath.Join(base, "agent-lifecycle.lock"))
	if err != nil || !expected.Mode().IsRegular() || !os.SameFile(info, expected) {
		return reject()
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return reject()
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = file.Close() }) }
	if ctx.Err() != nil {
		release()
		return nil, ctx.Err()
	}
	return release, nil
}
