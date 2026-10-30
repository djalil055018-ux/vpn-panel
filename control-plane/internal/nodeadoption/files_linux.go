package nodeadoption

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0
}
func directory(name string, private bool) bool {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return false
	}
	resolved, e := filepath.EvalSymlinks(name)
	if e != nil || resolved != name {
		return false
	}
	info, e := os.Lstat(name)
	return e == nil && info.IsDir() && owned(info) && (!private || info.Mode().Perm() == 0700)
}
func readAt(root *os.Root, name string, limit int64) ([]byte, error) {
	if name == "." || !filepath.IsLocal(name) {
		return nil, ErrMaterial
	}
	// Check directory ownership as well as final-file ownership. OpenRoot keeps
	// symlink resolution within the selected mount, including LE live/archive.
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		info, e := root.Stat(strings.Join(parts[:i], "/"))
		if e != nil || !info.IsDir() || !owned(info) {
			return nil, ErrMaterial
		}
	}
	f, e := root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if e != nil {
		return nil, ErrMaterial
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || !owned(before) || before.Size() > limit {
		return nil, ErrMaterial
	}
	// Inspect the resolved descriptor path too: a live/ certificate symlink may
	// point into archive/, whose directories must also be owner controlled.
	actual, e := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if e != nil {
		return nil, ErrMaterial
	}
	resolved, e := filepath.Rel(root.Name(), actual)
	if e != nil || !filepath.IsLocal(resolved) {
		return nil, ErrMaterial
	}
	parts = strings.Split(resolved, "/")
	for i := 1; i < len(parts); i++ {
		info, e := root.Stat(strings.Join(parts[:i], "/"))
		if e != nil || !info.IsDir() || !owned(info) {
			return nil, ErrMaterial
		}
	}
	data, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(data)) > limit {
		return nil, ErrMaterial
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !owned(after) {
		return nil, ErrMaterial
	}
	return data, nil
}

// ReadInput reads a bounded, owner-controlled local file without accepting
// symlink input names or changing any source permission.
func ReadInput(name string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, ErrMaterial
	}
	resolved, e := filepath.EvalSymlinks(name)
	if e != nil || resolved != name {
		return nil, ErrMaterial
	}
	parent := filepath.Dir(name)
	if !directory(parent, false) {
		return nil, ErrMaterial
	}
	root, e := os.OpenRoot(parent)
	if e != nil {
		return nil, ErrMaterial
	}
	defer root.Close()
	return readAt(root, filepath.Base(name), limit)
}
func validMounts(mounts []Mount) bool {
	if len(mounts) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, m := range mounts {
		if !path.IsAbs(m.ContainerPath) || path.Clean(m.ContainerPath) != m.ContainerPath || seen[m.ContainerPath] || !directory(m.HostPath, false) {
			return false
		}
		seen[m.ContainerPath] = true
	}
	return true
}
func readMounted(mounts []Mount, name string) ([]byte, error) {
	if !path.IsAbs(name) || path.Clean(name) != name {
		return nil, ErrMaterial
	}
	var match *Mount
	for i := range mounts {
		m := &mounts[i]
		if (m.ContainerPath == "/" || strings.HasPrefix(name, m.ContainerPath+"/")) && (match == nil || len(m.ContainerPath) > len(match.ContainerPath)) {
			match = m
		}
	}
	if match == nil {
		return nil, ErrMaterial
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(name, match.ContainerPath), "/")
	root, e := os.OpenRoot(match.HostPath)
	if e != nil {
		return nil, ErrMaterial
	}
	defer root.Close()
	return readAt(root, relative, 65536)
}
