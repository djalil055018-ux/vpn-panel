//go:build linux

package hysteria

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const ManagedAccount = "vpnplatform-hysteria"

var managedAccountName = regexp.MustCompile(`^(vpnplatform-hysteria|vpnplatform-hytest-[0-9a-f]{8})$`)
var ErrManagedAccount = errors.New("Hysteria managed account unavailable or unsafe")

type ManagedIdentity struct{ UID, GID int }
type accountRunner func(context.Context, string, ...string) ([]byte, int, error)

func runAccountCommand(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).Output()
	if ctx.Err() != nil {
		return nil, -1, ErrManagedAccount
	}
	if err == nil {
		return output, 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil, exit.ExitCode(), nil
	}
	return nil, -1, ErrManagedAccount
}
func groupIdentity(raw []byte, name string) (int, error) {
	if len(raw) > 4096 {
		return 0, ErrManagedAccount
	}
	parts := strings.Split(strings.TrimSuffix(string(raw), "\n"), ":")
	if len(parts) != 4 || parts[0] != name || parts[3] != "" {
		return 0, ErrManagedAccount
	}
	gid, err := strconv.Atoi(parts[2])
	if err != nil || !validRuntimeIdentity(1, gid) {
		return 0, ErrManagedAccount
	}
	return gid, nil
}
func accountIdentity(raw []byte, name string, gid int) (ManagedIdentity, error) {
	if len(raw) > 4096 {
		return ManagedIdentity{}, ErrManagedAccount
	}
	parts := strings.Split(strings.TrimSuffix(string(raw), "\n"), ":")
	if len(parts) != 7 || parts[0] != name || parts[5] != "/nonexistent" || parts[6] != "/usr/sbin/nologin" {
		return ManagedIdentity{}, ErrManagedAccount
	}
	uid, err := strconv.Atoi(parts[2])
	actualGroup, groupErr := strconv.Atoi(parts[3])
	if err != nil || groupErr != nil || actualGroup != gid || !validRuntimeIdentity(uid, gid) {
		return ManagedIdentity{}, ErrManagedAccount
	}
	return ManagedIdentity{uid, gid}, nil
}
func exclusiveGroup(raw []byte, name string, gid int) bool {
	if len(raw) > 1<<20 {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return false
		}
		primary, err := strconv.Atoi(fields[3])
		if err != nil {
			return false
		}
		if primary == gid && fields[0] != name {
			return false
		}
	}
	return true
}
func exclusiveIdentity(accounts, groups []byte, name string, identity ManagedIdentity) bool {
	if len(accounts) > 1<<20 || len(groups) > 1<<20 {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(accounts)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return false
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || (uid == identity.UID && fields[0] != name) {
			return false
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(groups)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			return false
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil || (gid == identity.GID && fields[0] != name) {
			return false
		}
		if fields[0] != name {
			for _, member := range strings.Split(fields[3], ",") {
				if member == name {
					return false
				}
			}
		}
	}
	return true
}

// EnsureManagedAccount never adopts a login-capable user, root identity, shared
// group or unexpected home directory. Existing accounts are validated, never
// modified. Partial creation can be retried; rollback does not recycle UID/GID
// while private runtime files may still belong to that identity.
func EnsureManagedAccount(ctx context.Context) (ManagedIdentity, error) {
	if os.Geteuid() != 0 {
		return ManagedIdentity{}, ErrManagedAccount
	}
	return ensureAccount(ctx, ManagedAccount, runAccountCommand)
}

// Normal agent startup only reads the installed identity. Account creation is
// reserved for the guarded provisioning command, never an automatic repair.
func ReadManagedAccount(ctx context.Context) (ManagedIdentity, error) {
	if os.Geteuid() != 0 {
		return ManagedIdentity{}, ErrManagedAccount
	}
	return readAccount(ctx, ManagedAccount, runAccountCommand)
}
func readAccount(ctx context.Context, name string, run accountRunner) (ManagedIdentity, error) {
	return ensureAccount(ctx, name, func(ctx context.Context, program string, args ...string) ([]byte, int, error) {
		if program != "getent" && (program != "passwd" || len(args) != 2 || args[0] != "-S") {
			return nil, -1, ErrManagedAccount
		}
		return run(ctx, program, args...)
	})
}
func ensureAccount(ctx context.Context, name string, run accountRunner) (ManagedIdentity, error) {
	var empty ManagedIdentity
	if !managedAccountName.MatchString(name) || ctx.Err() != nil {
		return empty, ErrManagedAccount
	}
	group, code, err := run(ctx, "getent", "group", name)
	if err != nil || (code != 0 && code != 2) {
		return empty, ErrManagedAccount
	}
	if code == 2 {
		// Refuse a pre-existing unexpected user before creating any group.
		_, userCode, userErr := run(ctx, "getent", "passwd", name)
		if userErr != nil || userCode != 2 {
			return empty, ErrManagedAccount
		}
		if _, createCode, createErr := run(ctx, "groupadd", "--system", name); createErr != nil || createCode != 0 {
			return empty, ErrManagedAccount
		}
		group, code, err = run(ctx, "getent", "group", name)
		if err != nil || code != 0 {
			return empty, ErrManagedAccount
		}
	}
	gid, err := groupIdentity(group, name)
	if err != nil {
		return empty, err
	}
	all, code, err := run(ctx, "getent", "passwd")
	if err != nil || code != 0 || !exclusiveGroup(all, name, gid) {
		return empty, ErrManagedAccount
	}
	account, code, err := run(ctx, "getent", "passwd", name)
	if err != nil || (code != 0 && code != 2) {
		return empty, ErrManagedAccount
	}
	if code == 2 {
		if _, code, err = run(ctx, "useradd", "--system", "--gid", name, "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", name); err != nil || code != 0 {
			return empty, ErrManagedAccount
		}
		account, code, err = run(ctx, "getent", "passwd", name)
		if err != nil || code != 0 {
			return empty, ErrManagedAccount
		}
	}
	identity, err := accountIdentity(account, name, gid)
	if err != nil {
		return empty, err
	}
	// Recheck membership after creation; concurrent local account changes cannot
	// make a newly shared group pass unnoticed at the end of provisioning.
	group, code, err = run(ctx, "getent", "group", name)
	if err != nil || code != 0 {
		return empty, ErrManagedAccount
	}
	checked, err := groupIdentity(group, name)
	if err != nil || checked != gid {
		return empty, ErrManagedAccount
	}
	all, code, err = run(ctx, "getent", "passwd")
	if err != nil || code != 0 || !exclusiveGroup(all, name, gid) {
		return empty, ErrManagedAccount
	}
	groups, code, err := run(ctx, "getent", "group")
	if err != nil || code != 0 || !exclusiveIdentity(all, groups, name, identity) {
		return empty, ErrManagedAccount
	}
	status, code, err := run(ctx, "passwd", "-S", name)
	fields := strings.Fields(string(status))
	if err != nil || code != 0 || len(fields) < 2 || fields[0] != name || fields[1] != "L" {
		return empty, ErrManagedAccount
	}
	return identity, nil
}
