//go:build linux

package pptp

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestManagedUnitRestrictiveUmaskAndRepair(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("managed units require root ownership")
	}
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "pptp.service")
	content := "[Service]\nExecStart=/usr/local/bin/vpn-node-agent\n"
	if err := managedFile(path, content); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("caller umask changed managed unit permissions")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = managedFile(path, content); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("matching private unit was not normalized")
	}
	if managedFile(path, content+"unexpected\n") == nil {
		t.Fatal("different unit was overwritten")
	}
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if managedFile(path, content) == nil {
		t.Fatal("writable unit accepted")
	}
	link := filepath.Join(filepath.Dir(path), "link.service")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if managedFile(link, content) == nil {
		t.Fatal("symlink unit accepted")
	}
}
