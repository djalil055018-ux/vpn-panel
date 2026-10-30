//go:build linux

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestTrafficCaptureSharedLockOrdersIndependentWorkers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	first, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	reserved := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- CaptureTrafficToOutbox(context.Background(), first, func(context.Context, bool) (*model.TrafficDelivery, error) {
			close(reserved)
			<-release
			v := outboxFixture(1)
			return &v, nil
		})
	}()
	<-reserved
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	called := false
	err = CaptureTrafficToOutbox(ctx, second, func(context.Context, bool) (*model.TrafficDelivery, error) {
		called = true
		v := outboxFixture(2)
		return &v, nil
	})
	close(release)
	if firstErr := <-done; firstErr != nil {
		t.Fatal(firstErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal("waiting capture bypassed shared lock or cancellation")
	}
	if err = CaptureTrafficToOutbox(context.Background(), second, func(context.Context, bool) (*model.TrafficDelivery, error) { v := outboxFixture(2); return &v, nil }); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []int64{1, 2} {
		v, err := second.Peek()
		if err != nil || v == nil || v.Snapshot.Sequence != seq {
			t.Fatal("sample order changed")
		}
		if second.Acknowledge(seq) != nil {
			t.Fatal("ack failed")
		}
	}
}

func TestTrafficCaptureLockAcrossProcess(t *testing.T) {
	if os.Getenv("VPN_TEST_CAPTURE_LOCK_CHILD") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		unlock, err := lockTrafficCapture(ctx, os.Getenv("VPN_TEST_CAPTURE_LOCK_DIR"))
		if unlock != nil {
			unlock()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("child bypassed process lock")
		}
		return
	}
	dir := filepath.Join(t.TempDir(), "outbox")
	unlock, err := lockTrafficCapture(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTrafficCaptureLockAcrossProcess$")
	child.Env = append(os.Environ(), "VPN_TEST_CAPTURE_LOCK_CHILD=1", "VPN_TEST_CAPTURE_LOCK_DIR="+dir)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("cross-process locking failed: %v %s", err, output)
	}
}

func TestTrafficCaptureRejectsUnsafeLock(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "other_owner"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "other_owner" && os.Geteuid() != 0 {
				t.Skip("requires root")
			}
			root := t.TempDir()
			path := filepath.Join(root, "traffic-capture.lock")
			if os.WriteFile(path, []byte{}, 0600) != nil {
				t.Fatal("fixture")
			}
			switch kind {
			case "symlink":
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "public":
				os.Chmod(path, 0644)
			case "other_owner":
				os.Chown(path, 65534, 65534)
			}
			unlock, err := lockTrafficCapture(context.Background(), filepath.Join(root, "outbox"))
			if unlock != nil {
				unlock()
			}
			if err == nil {
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}

func TestTrafficCaptureRefreshesFailedCachedSampleAfterHelperAdvancesSequence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	outbox, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	worker := &TrafficWorker{outbox: outbox, collect: func(_ context.Context, force bool) (*model.TrafficDelivery, error) {
		sequence := int64(1)
		if force {
			sequence = 3
		}
		v := outboxFixture(sequence)
		return &v, nil
	}}
	outbox.maxRecords = 0
	if !errors.Is(worker.Capture(context.Background(), false), ErrTrafficOutboxFull) {
		t.Fatal("queue failure not injected")
	}
	helper, err := NewTrafficOutbox(dir, outboxTestNode)
	if err != nil {
		t.Fatal(err)
	}
	if err = CaptureTrafficToOutbox(context.Background(), helper, func(context.Context, bool) (*model.TrafficDelivery, error) { v := outboxFixture(2); return &v, nil }); err != nil {
		t.Fatal(err)
	}
	outbox.maxRecords = 4096
	if err = worker.Capture(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []int64{2, 3} {
		v, err := outbox.Peek()
		if err != nil || v == nil || v.Snapshot.Sequence != sequence {
			t.Fatal("failed cached sample arrived after newer helper sample")
		}
		if outbox.Acknowledge(sequence) != nil {
			t.Fatal("ack failed")
		}
	}
}
