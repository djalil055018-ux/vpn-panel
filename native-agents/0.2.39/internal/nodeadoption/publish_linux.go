package nodeadoption

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type manifest struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
	Links   map[string]string `json:"links"`
}

func relative(name string) bool {
	return filepath.IsLocal(name) && name != "." && path.Clean(name) == name && !strings.Contains(name, "\\")
}
func bundleFiles(b *Bundle) (map[string][]byte, map[string]bool, string, error) {
	if b == nil || (b.Inspection == nil && b.Planning == nil) || (b.Planning != nil && (b.Inspection != nil || b.Stage != nil)) || len(b.Files) == 0 || len(b.Files) > 1024 || len(b.Links) > 128 {
		return nil, nil, "", ErrOutput
	}
	files := map[string][]byte{}
	dirs := map[string]bool{".": true}
	m := manifest{Version: 1, Files: map[string]string{}, Links: map[string]string{}}
	for name, data := range b.Files {
		if !relative(name) || name == "manifest.json" || len(data) > 4<<20 {
			return nil, nil, "", ErrOutput
		}
		files[name] = data
		m.Files[name] = digest(data)
	}
	for name, target := range b.Links {
		// Only agent certificate pointers may be symlinks in a bundle.
		parts := strings.Split(name, "/")
		if len(parts) != 4 || parts[0] != "node-data" || parts[1] != "certificates" || !idPattern.MatchString(parts[2]) || parts[3] != "current" || !strings.HasPrefix(target, "versions/") || !hashPattern.MatchString(strings.TrimPrefix(target, "versions/")) {
			return nil, nil, "", ErrOutput
		}
		base := path.Join(path.Dir(name), target)
		if _, ok := files[base+"/fullchain.pem"]; !ok {
			return nil, nil, "", ErrOutput
		}
		if _, ok := files[base+"/private.key"]; !ok {
			return nil, nil, "", ErrOutput
		}
		if _, ok := files[name]; ok {
			return nil, nil, "", ErrOutput
		}
		m.Links[name] = target
	}
	all := []string{}
	for name := range files {
		all = append(all, name)
	}
	for name := range b.Links {
		all = append(all, name)
	}
	for _, name := range all {
		for d := path.Dir(name); d != "."; d = path.Dir(d) {
			if _, ok := files[d]; ok {
				return nil, nil, "", ErrOutput
			}
			if _, ok := b.Links[d]; ok {
				return nil, nil, "", ErrOutput
			}
			dirs[d] = true
		}
	}
	raw := encoded(m)
	files["manifest.json"] = raw
	return files, dirs, digest(raw), nil
}
func matches(out string, files map[string][]byte, dirs map[string]bool, links map[string]string) bool {
	if !directory(out, true) {
		return false
	}
	seen := map[string]bool{}
	err := filepath.WalkDir(out, func(name string, d fs.DirEntry, e error) error {
		if e != nil {
			return ErrOutput
		}
		rel, e := filepath.Rel(out, name)
		if e != nil {
			return ErrOutput
		}
		info, e := os.Lstat(name)
		if e != nil {
			return ErrOutput
		}
		if target, ok := links[rel]; ok {
			actual, e := os.Readlink(name)
			if e != nil || actual != target {
				return ErrOutput
			}
			seen[rel] = true
			return nil
		}
		if !owned(info) {
			return ErrOutput
		}
		if dirs[rel] {
			if !info.IsDir() || info.Mode().Perm() != 0700 {
				return ErrOutput
			}
			seen[rel] = true
			return nil
		}
		want, ok := files[rel]
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(len(want)) {
			return ErrOutput
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return ErrOutput
		}
		actual, e := os.ReadFile(name)
		if e != nil || !bytes.Equal(actual, want) {
			return ErrOutput
		}
		seen[rel] = true
		return nil
	})
	return err == nil && len(seen) == len(files)+len(dirs)+len(links)
}
func syncDir(name string) error {
	f, e := os.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// Publish never overwrites an output path. The staged directory is fully
// synchronized before a Linux RENAME_NOREPLACE publication; an exact retry is
// read-only. A conflicting, partial or permissions-altered directory is refused.
func Publish(out string, b *Bundle) (Summary, error) {
	var result Summary
	files, dirs, sha, e := bundleFiles(b)
	if e != nil {
		return result, ErrOutput
	}
	if !filepath.IsAbs(out) || filepath.Clean(out) != out || out == "/" || !directory(filepath.Dir(out), true) {
		return result, ErrOutput
	}
	result = Summary{ManifestSHA256: sha, Files: len(files), Links: len(b.Links)}
	if b.Inspection != nil {
		result.Kind = b.Inspection.Receipt.Kind
		result.InspectionSHA256 = b.Inspection.SHA256
		result.MaterialSHA256 = b.Inspection.MaterialSHA256
	}
	if b.Planning != nil {
		result.Kind = b.Planning.Kind
		result.PlanSHA256 = b.Planning.PlanSHA256
	}
	if b.Stage != nil {
		result.Kind = b.Stage.Kind
	}
	if _, e = os.Lstat(out); e == nil {
		if !matches(out, files, dirs, b.Links) {
			return Summary{}, ErrOutput
		}
		result.Existing = true
		return result, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return Summary{}, ErrOutput
	}
	parent := filepath.Dir(out)
	temp, e := os.MkdirTemp(parent, ".node-material-")
	if e != nil {
		return Summary{}, ErrOutput
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temp)
		}
	}()
	names := []string{}
	for d := range dirs {
		if d != "." {
			names = append(names, d)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if os.MkdirAll(filepath.Join(temp, name), 0700) != nil {
			return Summary{}, ErrOutput
		}
	}
	for name, data := range files {
		f, e := os.OpenFile(filepath.Join(temp, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return Summary{}, ErrOutput
		}
		_, we := f.Write(data)
		se := f.Sync()
		ce := f.Close()
		if we != nil || se != nil || ce != nil {
			return Summary{}, ErrOutput
		}
	}
	for name, target := range b.Links {
		if os.Symlink(target, filepath.Join(temp, name)) != nil {
			return Summary{}, ErrOutput
		}
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, name := range names {
		if syncDir(filepath.Join(temp, name)) != nil {
			return Summary{}, ErrOutput
		}
	}
	if syncDir(temp) != nil {
		return Summary{}, ErrOutput
	}
	fd, e := unix.Open(parent, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return Summary{}, ErrOutput
	}
	defer unix.Close(fd)
	if e = unix.Renameat2(fd, filepath.Base(temp), fd, filepath.Base(out), unix.RENAME_NOREPLACE); e != nil {
		if errors.Is(e, unix.EEXIST) && matches(out, files, dirs, b.Links) {
			result.Existing = true
			return result, nil
		}
		return Summary{}, ErrOutput
	}
	published = true
	if unix.Fsync(fd) != nil || !matches(out, files, dirs, b.Links) {
		return Summary{}, ErrOutput
	}
	return result, nil
}
