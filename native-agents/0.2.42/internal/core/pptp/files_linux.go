//go:build linux

package pptp

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrRuntime = errors.New("PPTP runtime unavailable or requires repair")

func privateDirectory(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return ErrRuntime
	}
	// Every ancestor must be a real, root-owned directory; writable shared parents
	// would permit replacing the private subtree while the daemon is running.
	for p := path; p != "/"; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if os.IsNotExist(err) && p == path && create {
			if err = os.Mkdir(p, 0700); err != nil {
				return err
			}
			info, err = os.Lstat(p)
		}
		if err != nil || !info.IsDir() {
			return ErrRuntime
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrRuntime
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0700 {
		return ErrRuntime
	}
	return nil
}
func readPrivate(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := i.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || i.Size() > max {
		return nil, ErrRuntime
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}
func writePrivate(path string, raw []byte) error {
	parent := filepath.Dir(path)
	if err := privateDirectory(parent, false); err != nil {
		return err
	}
	f, err := os.CreateTemp(parent, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
