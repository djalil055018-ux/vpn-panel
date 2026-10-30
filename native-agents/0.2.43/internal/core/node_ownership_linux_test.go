//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestInheritedNodeOwnershipChildDoesNotReleaseParentLock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("VPN_TEST_INHERITED_OWNER_CHILD") == "1" {
		release, err := AdoptNodeOwnershipFD(context.Background(), os.Getenv("VPN_TEST_OWNER_BASE"), 3)
		if err != nil {
			t.Fatal("inherited ownership rejected")
		}
		release()
		release()
		return
	}
	base := t.TempDir()
	file, err := os.OpenFile(filepath.Join(base, "agent-lifecycle.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("parent lock failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInheritedNodeOwnershipChildDoesNotReleaseParentLock$")
	cmd.Env = append(os.Environ(), "VPN_TEST_INHERITED_OWNER_CHILD=1", "VPN_TEST_OWNER_BASE="+base)
	cmd.ExtraFiles = []*os.File{file}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("inherited owner failed: %v %s", err, output)
	}
	if release, err := AcquireNodeOwnership(context.Background(), base); err == nil {
		release()
		t.Fatal("child released parent lock")
	}
	syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	release, err := AcquireNodeOwnership(context.Background(), base)
	if err != nil {
		t.Fatal("released lock not reusable")
	}
	release()
}

func TestInheritedNodeOwnershipRejectsWrongDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	base := t.TempDir()
	file, err := os.CreateTemp(base, "unrelated")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	duplicate, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if release, err := AdoptNodeOwnershipFD(context.Background(), base, duplicate); err == nil {
		release()
		t.Fatal("unrelated file adopted")
	}
	for _, descriptor := range []int{-1, 0, 1, 2} {
		if _, err := AdoptNodeOwnershipFD(context.Background(), base, descriptor); err == nil {
			t.Fatal("standard descriptor accepted")
		}
	}
}

func TestNodeOwnershipExcludesOtherProcessAndReleasesOnExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	if os.Getenv("VPN_TEST_OWNER_CHILD") == "1" {
		release, err := AcquireNodeOwnership(context.Background(), os.Getenv("VPN_TEST_OWNER_BASE"))
		if release != nil {
			release()
		}
		if !errors.Is(err, ErrNodeOwnership) {
			t.Fatal("child acquired owned node")
		}
		return
	}
	base := t.TempDir()
	release, err := AcquireNodeOwnership(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeOwnershipExcludesOtherProcessAndReleasesOnExit$")
	cmd.Env = append(os.Environ(), "VPN_TEST_OWNER_CHILD=1", "VPN_TEST_OWNER_BASE="+base)
	output, childErr := cmd.CombinedOutput()
	release()
	release()
	if childErr != nil {
		t.Fatalf("cross-process exclusion failed: %v %s", childErr, output)
	}
	again, err := AcquireNodeOwnership(context.Background(), base)
	if err != nil {
		t.Fatal("released node remained locked")
	}
	again()
	if _, err := os.Stat(filepath.Join(base, "agent-lifecycle.lock")); err != nil {
		t.Fatal("lock inode removed")
	}
}

func TestNodeOwnershipCancellationAndUnsafePaths(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	base := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AcquireNodeOwnership(ctx, base); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if _, err := os.Stat(filepath.Join(base, "agent-lifecycle.lock")); !os.IsNotExist(err) {
		t.Fatal("cancelled acquisition created lock")
	}
	for _, kind := range []string{"symlink", "public", "owner", "directory"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "agent-lifecycle.lock")
			os.WriteFile(path, []byte{}, 0600)
			switch kind {
			case "symlink":
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "public":
				os.Chmod(path, 0644)
			case "owner":
				os.Chown(path, 65534, 65534)
			case "directory":
				os.Remove(path)
				os.Mkdir(path, 0700)
			}
			release, err := AcquireNodeOwnership(context.Background(), base)
			if release != nil {
				release()
			}
			if err == nil {
				t.Fatal("unsafe ownership lock accepted")
			}
		})
	}
}
