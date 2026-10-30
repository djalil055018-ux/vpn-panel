//go:build linux

package hysteria

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

type accountFixture struct {
	group, user                                              bool
	members, home, shell, other, otherGroups, passwordStatus string
	creates                                                  int
}

func (f *accountFixture) run(ctx context.Context, program string, args ...string) ([]byte, int, error) {
	name := ManagedAccount
	if program == "getent" {
		if args[0] == "group" {
			if !f.group {
				return nil, 2, nil
			}
			raw := name + ":x:999:" + f.members + "\n"
			if len(args) == 1 {
				raw += f.otherGroups
			}
			return []byte(raw), 0, nil
		}
		row := name + ":x:998:999::" + f.home + ":" + f.shell + "\n"
		if len(args) == 1 {
			all := "root:x:0:0:root:/root:/bin/bash\n" + f.other
			if f.user {
				all += row
			}
			return []byte(all), 0, nil
		}
		if !f.user {
			return nil, 2, nil
		}
		return []byte(row), 0, nil
	}
	if program == "groupadd" {
		f.group = true
		f.creates++
		return nil, 0, nil
	}
	if program == "useradd" {
		if strings.Join(args, " ") != "--system --gid "+name+" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "+name {
			return nil, 1, nil
		}
		f.user = true
		f.home = "/nonexistent"
		f.shell = "/usr/sbin/nologin"
		f.creates++
		return nil, 0, nil
	}
	if program == "passwd" {
		status := f.passwordStatus
		if status == "" {
			status = "L"
		}
		return []byte(name + " " + status + " 2026-09-13 0 99999 7 -1\n"), 0, nil
	}
	return nil, 1, nil
}
func TestManagedAccountCreatesRestrictedIdentityAndReplaysWithoutMutation(t *testing.T) {
	fixture := &accountFixture{}
	first, err := ensureAccount(context.Background(), ManagedAccount, fixture.run)
	if err != nil || first.UID != 998 || first.GID != 999 || fixture.creates != 2 {
		t.Fatal("restricted creation failed", err)
	}
	again, err := ensureAccount(context.Background(), ManagedAccount, fixture.run)
	if err != nil || again != first || fixture.creates != 2 {
		t.Fatal("replay mutated account")
	}
}

func TestReadManagedAccountNeverCreatesOrRepairsIdentity(t *testing.T) {
	for _, existing := range []bool{false, true} {
		fixture := &accountFixture{group: existing, user: existing, home: "/nonexistent", shell: "/usr/sbin/nologin"}
		identity, err := readAccount(context.Background(), ManagedAccount, fixture.run)
		if fixture.creates != 0 {
			t.Fatal("read created account")
		}
		if existing {
			if err != nil || identity.UID != 998 || identity.GID != 999 {
				t.Fatal("valid installed identity rejected")
			}
		} else if err == nil {
			t.Fatal("missing installed identity accepted")
		}
	}
}
func TestManagedAccountRejectsSharedOrLoginCapableExistingIdentity(t *testing.T) {
	for _, kind := range []string{"members", "primary_member", "shell", "home", "user_without_group", "uid_alias", "supplementary", "unlocked_password"} {
		t.Run(kind, func(t *testing.T) {
			fixture := &accountFixture{group: true, user: true, home: "/nonexistent", shell: "/usr/sbin/nologin"}
			switch kind {
			case "members":
				fixture.members = "outsider"
			case "primary_member":
				fixture.other = "outsider:x:500:999::/home/outsider:/bin/bash\n"
			case "shell":
				fixture.shell = "/bin/bash"
			case "home":
				fixture.home = "/root"
			case "user_without_group":
				fixture.group = false
			case "uid_alias":
				fixture.other = "alias:x:998:998::/nonexistent:/usr/sbin/nologin\n"
			case "supplementary":
				fixture.otherGroups = "sudo:x:27:" + ManagedAccount + "\n"
			case "unlocked_password":
				fixture.passwordStatus = "P"
			}
			if _, err := ensureAccount(context.Background(), ManagedAccount, fixture.run); err == nil || fixture.creates != 0 {
				t.Fatal("unsafe existing identity adopted or modified")
			}
		})
	}
}
func TestNativeManagedAccountInDisposableContainer(t *testing.T) {
	if os.Getenv("HYSTERIA_NATIVE_ACCOUNT") != "1" {
		t.Skip("requires explicit disposable-container opt-in")
	}
	// Do not allow this test to create host accounts even when opt-in is inherited.
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("native account test requires a disposable Docker container")
	}
	entropy := make([]byte, 4)
	if _, err := rand.Read(entropy); err != nil {
		t.Fatal(err)
	}
	name := "vpnplatform-hytest-" + hex.EncodeToString(entropy)
	identity, err := ensureAccount(context.Background(), name, runAccountCommand)
	if err != nil {
		t.Fatal("native account creation failed")
	}
	again, err := ensureAccount(context.Background(), name, runAccountCommand)
	if err != nil || again != identity {
		t.Fatal("native account replay failed")
	}
	raw, code, err := runAccountCommand(context.Background(), "getent", "passwd", name)
	if err != nil || code != 0 || !strings.Contains(string(raw), fmt.Sprintf(":%d:%d:", identity.UID, identity.GID)) {
		t.Fatal("native identity mismatch")
	}
	t.Log("restricted account created and verified in disposable container")
}
