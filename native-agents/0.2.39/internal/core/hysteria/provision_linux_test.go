//go:build linux

package hysteria

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func provisionFixture(t *testing.T) (unitProvisioner, *int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	directory := t.TempDir()
	calls := 0
	p := unitProvisioner{directory: directory, unit: ManagedService, owner: ManagedAgentService}
	p.run = func(ctx context.Context, args ...string) ([]byte, error) {
		calls++
		if args[0] == "daemon-reload" {
			return nil, nil
		}
		if args[0] == "show" {
			return []byte("FragmentPath=" + filepath.Join(directory, ManagedService) + "\nDropInPaths=\nNeedDaemonReload=no\n"), nil
		}
		t.Error("provisioner attempted runtime start/stop")
		return nil, ErrProvision
	}
	return p, &calls
}
func TestUnitProvisionPublishesWithoutStartingAndReplaysAfterReloadFailure(t *testing.T) {
	p, calls := provisionFixture(t)
	run := p.run
	fail := true
	p.run = func(ctx context.Context, args ...string) ([]byte, error) {
		if fail {
			fail = false
			return nil, errors.New("injected reload failure")
		}
		return run(ctx, args...)
	}
	if err := p.ensure(context.Background(), "/var/lib/vpn-platform", ManagedIdentity{998, 999}); err == nil {
		t.Fatal("reload failure accepted")
	}
	path := filepath.Join(p.directory, p.unit)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal("published unit lost", err)
	}
	if err = p.ensure(context.Background(), "/var/lib/vpn-platform", ManagedIdentity{998, 999}); err != nil {
		t.Fatal("retry failed", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || *calls != 2 {
		t.Fatal("retry replaced unit or changed runtime")
	}
}
func TestUnitProvisionRejectsUnrecognizedFilesAndDropins(t *testing.T) {
	for _, kind := range []string{"unexpected", "symlink", "public_write", "dropin"} {
		t.Run(kind, func(t *testing.T) {
			p, calls := provisionFixture(t)
			path := filepath.Join(p.directory, p.unit)
			if kind == "dropin" {
				p.run = func(context.Context, ...string) ([]byte, error) {
					return []byte("FragmentPath=" + path + "\nDropInPaths=/etc/override.conf\nNeedDaemonReload=no\n"), nil
				}
			} else {
				if os.WriteFile(path, []byte("unrecognized unit"), 0644) != nil {
					t.Fatal("fixture failed")
				}
				if kind == "symlink" {
					if os.Rename(path, path+".original") != nil || os.Symlink(path+".original", path) != nil {
						t.Fatal("fixture failed")
					}
				}
				if kind == "public_write" {
					if os.Chmod(path, 0666) != nil {
						t.Fatal("fixture failed")
					}
				}
			}
			if err := p.ensure(context.Background(), "/var/lib/vpn-platform", ManagedIdentity{998, 999}); err == nil {
				t.Fatal("unrecognized unit configuration accepted")
			}
			if kind != "dropin" && *calls != 0 {
				t.Fatal("unsafe unit caused manager mutation")
			}
		})
	}
}
func TestUnitProvisionCancelledBeforePublication(t *testing.T) {
	p, calls := provisionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.ensure(ctx, "/var/lib/vpn-platform", ManagedIdentity{998, 999}) == nil {
		t.Fatal("cancelled provision succeeded")
	}
	if *calls != 0 {
		t.Fatal("cancelled provision called service manager")
	}
	if _, err := os.Lstat(filepath.Join(p.directory, p.unit)); !os.IsNotExist(err) {
		t.Fatal("cancelled provision created unit")
	}
}

func TestUnitVerificationIsReadOnlyAndRejectsDrift(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "changed", "dropin", "wrong_fragment", "public_write", "reload_pending"} {
		t.Run(kind, func(t *testing.T) {
			p, _ := provisionFixture(t)
			identity := ManagedIdentity{998, 999}
			if p.ensure(context.Background(), "/var/lib/vpn-platform", identity) != nil {
				t.Fatal("fixture provisioning failed")
			}
			path := filepath.Join(p.directory, p.unit)
			switch kind {
			case "missing":
				os.Remove(path)
			case "changed":
				os.WriteFile(path, []byte("unexpected unit"), 0644)
			case "public_write":
				os.Chmod(path, 0666)
			}
			before, _ := os.Lstat(path)
			rawBefore, _ := os.ReadFile(path)
			p.run = func(_ context.Context, args ...string) ([]byte, error) {
				if args[0] != "show" {
					t.Fatal("verification mutated service manager")
				}
				fragment, dropin := path, ""
				if kind == "dropin" {
					dropin = "/etc/unreviewed.conf"
				}
				if kind == "wrong_fragment" {
					fragment = "/run/other.service"
				}
				reload := "no"
				if kind == "reload_pending" {
					reload = "yes"
				}
				return []byte("FragmentPath=" + fragment + "\nDropInPaths=" + dropin + "\nNeedDaemonReload=" + reload + "\n"), nil
			}
			err := p.verify(context.Background(), "/var/lib/vpn-platform", identity)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unit drift accepted")
			}
			after, statErr := os.Lstat(path)
			rawAfter, _ := os.ReadFile(path)
			if kind == "missing" {
				if !os.IsNotExist(statErr) {
					t.Fatal("missing unit recreated")
				}
			} else if statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || string(rawBefore) != string(rawAfter) {
				t.Fatal("read changed unit")
			}
		})
	}
}

func TestManagedBaseTraversalPreservesPrivateAgentAndKeyFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	base := t.TempDir()
	if os.Chmod(base, 0700) != nil {
		t.Fatal("fixture failed")
	}
	agent := filepath.Join(base, "agent")
	if os.Mkdir(agent, 0700) != nil {
		t.Fatal("fixture failed")
	}
	secret := filepath.Join(agent, "state.json")
	if os.WriteFile(secret, []byte("fixture-private-state"), 0600) != nil {
		t.Fatal("fixture failed")
	}
	before, err := os.Stat(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareManagedBase(base, ManagedIdentity{65534, 65534}); err != nil {
		t.Fatal(err)
	}
	root, err := os.Stat(base)
	if err != nil || root.Mode().Perm() != 0750 || !ownedBy(root, 0, 65534) {
		t.Fatal("managed group cannot traverse base")
	}
	private, err := os.Stat(agent)
	if err != nil || private.Mode().Perm() != 0700 {
		t.Fatal("private agent directory opened")
	}
	after, err := os.Stat(secret)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0600 || !ownedBy(after, 0, -1) {
		t.Fatal("private state permissions changed")
	}
}
