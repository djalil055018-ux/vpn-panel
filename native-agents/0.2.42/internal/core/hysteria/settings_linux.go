//go:build linux

package hysteria

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

var ErrRuntimeSettings = errors.New("Hysteria local runtime settings unavailable or invalid")

type runtimeSettings struct {
	Format           int    `json:"format"`
	UID              int    `json:"uid"`
	GID              int    `json:"gid"`
	AuthPort         int    `json:"auth_port"`
	StatisticsPort   int    `json:"statistics_port"`
	StatisticsSecret string `json:"statistics_secret"`
}

func (s runtimeSettings) options() compiler.HysteriaRuntimeOptions {
	return compiler.HysteriaRuntimeOptions{AuthPort: s.AuthPort, StatisticsPort: s.StatisticsPort, StatisticsSecret: s.StatisticsSecret}
}
func validRuntimeIdentity(uid, gid int) bool {
	return uid > 0 && gid > 0 && uint64(uid) <= math.MaxInt32 && uint64(gid) <= math.MaxInt32
}

// Settings are node-local and immutable once published. Restart must preserve
// endpoint ports and the statistics secret referenced by existing revisions.
// Corruption/identity drift is an error, never permission to silently regenerate.
// Reservation sockets avoid choosing the same TCP port during creation; the
// lifecycle still must bind/check both actual endpoints before starting a core.
func openRuntimeSettings(base string, uid, gid int) (runtimeSettings, error) {
	var empty runtimeSettings
	if os.Geteuid() != 0 || !validRuntimeIdentity(uid, gid) || !filepath.IsAbs(base) || filepath.Clean(base) != base || protectedDirectory(base, false) != nil {
		return empty, ErrRuntimeSettings
	}
	root := filepath.Join(base, "hysteria2")
	control := filepath.Join(root, "control")
	path := filepath.Join(control, "settings.json")
	read := func() (runtimeSettings, error) {
		for _, dir := range []string{root, control} {
			if protectedDirectory(dir, false) != nil {
				return empty, ErrRuntimeSettings
			}
		}
		info, err := os.Lstat(control)
		if err != nil || info.Mode().Perm() != 0700 {
			return empty, ErrRuntimeSettings
		}
		raw, err := readTLSFile(path, 4096, 0600, -1)
		if err != nil {
			return empty, ErrRuntimeSettings
		}
		var settings runtimeSettings
		if decodeStrict(raw, &settings) != nil || settings.Format != 1 || settings.UID != uid || settings.GID != gid {
			return empty, ErrRuntimeSettings
		}
		if _, err = compiler.CompileHysteria(model.DesiredState{Core: model.CoreRelease{Type: "hysteria2"}}, settings.options()); err != nil {
			return empty, ErrRuntimeSettings
		}
		return settings, nil
	}
	if _, err := os.Lstat(path); err == nil {
		return read()
	} else if !os.IsNotExist(err) {
		return empty, ErrRuntimeSettings
	}
	// A missing settings file next to an active revision is damage, not a fresh
	// installation. Do not generate a different secret behind existing configs.
	if _, err := os.Lstat(filepath.Join(root, "current")); err == nil || !os.IsNotExist(err) {
		return empty, ErrRuntimeSettings
	}
	if runtimeTLSDirectory(root, gid) != nil {
		return empty, ErrRuntimeSettings
	}
	if err := os.Mkdir(control, 0700); err != nil && !os.IsExist(err) {
		return empty, ErrRuntimeSettings
	}
	info, err := os.Lstat(control)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedBy(info, 0, -1) {
		return empty, ErrRuntimeSettings
	}
	auth, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return empty, ErrRuntimeSettings
	}
	defer auth.Close()
	stats, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return empty, ErrRuntimeSettings
	}
	defer stats.Close()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return empty, ErrRuntimeSettings
	}
	settings := runtimeSettings{1, uid, gid, auth.Addr().(*net.TCPAddr).Port, stats.Addr().(*net.TCPAddr).Port, hex.EncodeToString(secret)}
	raw, err := json.Marshal(settings)
	if err != nil {
		return empty, ErrRuntimeSettings
	}
	temp, err := os.CreateTemp(control, ".settings-")
	if err != nil {
		return empty, ErrRuntimeSettings
	}
	defer os.Remove(temp.Name())
	_, writeErr := temp.Write(raw)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return empty, ErrRuntimeSettings
	}
	// Hard-link publication cannot replace a concurrent winner or an existing
	// unsafe path. All callers subsequently read and validate the winning record.
	if err = os.Link(temp.Name(), path); err != nil && !os.IsExist(err) {
		return empty, ErrRuntimeSettings
	}
	if syncDirectory(control) != nil || syncDirectory(root) != nil {
		return empty, ErrRuntimeSettings
	}
	return read()
}
