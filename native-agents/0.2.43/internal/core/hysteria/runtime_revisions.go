package hysteria

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

var ErrRuntimeRevision = errors.New("Hysteria runtime revision unavailable or invalid")

type revisionMetadata struct {
	Format       int                `json:"format"`
	State        model.DesiredState `json:"state"`
	TLSVersion   string             `json:"tls_version"`
	ConfigSHA256 string             `json:"config_sha256"`
}
type runtimeRevision struct {
	id    string
	state model.DesiredState
}

func (r *runtimeRevision) idle() bool { return len(r.state.Services) == 0 }

type revisionStore struct {
	installer    *Installer
	certificates *CertificateRuntime
	options      compiler.HysteriaRuntimeOptions
}

func newRevisionStore(installer *Installer, certificates *CertificateRuntime, options compiler.HysteriaRuntimeOptions) (*revisionStore, error) {
	if installer == nil || certificates == nil || installer.base != certificates.base || certificates.gid <= 0 {
		return nil, ErrRuntimeRevision
	}
	if _, err := compiler.CompileHysteria(model.DesiredState{Core: model.CoreRelease{Type: "hysteria2"}}, options); err != nil {
		return nil, ErrRuntimeRevision
	}
	return &revisionStore{installer, certificates, options}, nil
}
func (s *revisionStore) root() string     { return filepath.Join(s.installer.base, "hysteria2") }
func (s *revisionStore) versions() string { return filepath.Join(s.root(), "revisions") }
func revisionHash(metadata, config []byte) string {
	hash := sha256.New()
	_, _ = hash.Write(metadata)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(config)
	return hex.EncodeToString(hash.Sum(nil))
}

// Staging never updates current. Generation/client grants belong to the access
// journal, not native runtime revisions: access additions must not cause restarts.
func (s *revisionStore) stage(ctx context.Context, state model.DesiredState) (*runtimeRevision, error) {
	binary, err := s.installer.destination(state.Core)
	if err != nil || s.installer.verify(ctx, binary) != nil {
		return nil, ErrRuntimeRevision
	}
	config, err := compiler.CompileHysteria(state, s.options)
	if err != nil || len(config) > 64<<10 {
		return nil, ErrRuntimeRevision
	}
	state.Generation = 0
	state.Core.Channel = ""
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	metadata := revisionMetadata{Format: 1}
	if len(state.Services) == 1 {
		service := &state.Services[0]
		service.Clients = nil
		copy := *service.TLS
		service.TLS = &copy
		digest := filepath.Base(filepath.Dir(service.TLS.KeyFile))
		resolved, err := s.certificates.published(copy, digest, true)
		if err != nil || resolved.CertificateFile != copy.CertificateFile || resolved.KeyFile != copy.KeyFile {
			return nil, ErrRuntimeRevision
		}
		metadata.TLSVersion = digest
	}
	metadata.State = state
	sum := sha256.Sum256(config)
	metadata.ConfigSHA256 = hex.EncodeToString(sum[:])
	raw, err := json.Marshal(metadata)
	if err != nil || len(raw) > 64<<10 || ctx.Err() != nil {
		return nil, ErrRuntimeRevision
	}
	id := revisionHash(raw, config)
	for _, dir := range []string{s.root(), s.versions()} {
		if runtimeTLSDirectory(dir, s.certificates.gid) != nil {
			return nil, ErrRuntimeRevision
		}
	}
	target := filepath.Join(s.versions(), id)
	if _, err = os.Lstat(target); os.IsNotExist(err) {
		temp, err := os.MkdirTemp(s.versions(), ".revision-")
		if err != nil {
			return nil, ErrRuntimeRevision
		}
		defer os.RemoveAll(temp)
		if writeRuntimeTLS(filepath.Join(temp, "metadata.json"), raw, s.certificates.gid) != nil {
			return nil, ErrRuntimeRevision
		}
		if len(state.Services) > 0 {
			if writeRuntimeTLS(filepath.Join(temp, "config.json"), config, s.certificates.gid) != nil || os.Symlink(binary, filepath.Join(temp, "hysteria")) != nil {
				return nil, ErrRuntimeRevision
			}
		}
		if os.Chown(temp, 0, s.certificates.gid) != nil || os.Chmod(temp, 0750) != nil || syncDirectory(temp) != nil || ctx.Err() != nil {
			return nil, ErrRuntimeRevision
		}
		if err = os.Rename(temp, target); err != nil {
			if _, existingErr := s.load(ctx, id, true); existingErr != nil {
				return nil, ErrRuntimeRevision
			}
		}
	} else if err != nil {
		return nil, ErrRuntimeRevision
	}
	if syncDirectory(s.versions()) != nil {
		return nil, ErrRuntimeRevision
	}
	return s.load(ctx, id, true)
}

func (s *revisionStore) load(ctx context.Context, id string, requireCurrentTLS bool) (*runtimeRevision, error) {
	if !materialDigest.MatchString(id) || ctx.Err() != nil {
		return nil, ErrRuntimeRevision
	}
	target := filepath.Join(s.versions(), id)
	for _, dir := range []string{s.installer.base, s.root(), s.versions(), target} {
		if protectedDirectory(dir, false) != nil {
			return nil, ErrRuntimeRevision
		}
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode().Perm() != 0750 || !ownedBy(info, 0, s.certificates.gid) {
		return nil, ErrRuntimeRevision
	}
	raw, err := readTLSFile(filepath.Join(target, "metadata.json"), 64<<10, 0640, s.certificates.gid)
	if err != nil {
		return nil, ErrRuntimeRevision
	}
	var metadata revisionMetadata
	if decodeStrict(raw, &metadata) != nil || metadata.Format != 1 || metadata.State.Generation != 0 || metadata.State.Core.Channel != "" || len(metadata.State.Services) > 1 {
		return nil, ErrRuntimeRevision
	}
	binary, err := s.installer.destination(metadata.State.Core)
	if err != nil || s.installer.verify(ctx, binary) != nil {
		return nil, ErrRuntimeRevision
	}
	var config []byte
	if len(metadata.State.Services) == 1 {
		service := &metadata.State.Services[0]
		if len(service.Clients) != 0 || service.TLS == nil {
			return nil, ErrRuntimeRevision
		}
		resolved, err := s.certificates.published(*service.TLS, metadata.TLSVersion, requireCurrentTLS)
		if err != nil {
			return nil, ErrRuntimeRevision
		}
		service.TLS = &resolved
		config, err = readTLSFile(filepath.Join(target, "config.json"), 64<<10, 0640, s.certificates.gid)
		if err != nil {
			return nil, ErrRuntimeRevision
		}
		link, err := os.Readlink(filepath.Join(target, "hysteria"))
		if err != nil || link != binary {
			return nil, ErrRuntimeRevision
		}
	} else {
		if metadata.TLSVersion != "" {
			return nil, ErrRuntimeRevision
		}
		for _, name := range []string{"config.json", "hysteria"} {
			if _, err := os.Lstat(filepath.Join(target, name)); !os.IsNotExist(err) {
				return nil, ErrRuntimeRevision
			}
		}
	}
	expected, err := compiler.CompileHysteria(metadata.State, s.options)
	if err != nil || !bytes.Equal(config, expected) {
		return nil, ErrRuntimeRevision
	}
	sum := sha256.Sum256(config)
	if metadata.ConfigSHA256 != hex.EncodeToString(sum[:]) {
		return nil, ErrRuntimeRevision
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || revisionHash(canonical, config) != id {
		return nil, ErrRuntimeRevision
	}
	return &runtimeRevision{id: id, state: metadata.State}, nil
}

func (s *revisionStore) current(ctx context.Context) (*runtimeRevision, error) {
	path := filepath.Join(s.root(), "current")
	link, err := os.Readlink(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrRuntimeRevision
	}
	id := filepath.Base(link)
	if link != filepath.Join("revisions", id) || !materialDigest.MatchString(id) {
		return nil, ErrRuntimeRevision
	}
	return s.load(ctx, id, false)
}

// Only the driver may call activate/restore, after confirming the core is fully
// stopped. These primitives deliberately do not claim a deployment is applied.
// An error after rename/fsync is uncertain activation and requires rollback.
func (s *revisionStore) activate(ctx context.Context, id string) error {
	if _, err := s.load(ctx, id, true); err != nil {
		return err
	}
	path := filepath.Join(s.root(), "current")
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return ErrRuntimeRevision
	} else if err != nil && !os.IsNotExist(err) {
		return ErrRuntimeRevision
	}
	file, err := os.CreateTemp(s.root(), ".current-")
	if err != nil {
		return ErrRuntimeRevision
	}
	temp := file.Name()
	if file.Close() != nil {
		return ErrRuntimeRevision
	}
	defer os.Remove(temp)
	if os.Remove(temp) != nil || os.Symlink(filepath.Join("revisions", id), temp) != nil || ctx.Err() != nil {
		return ErrRuntimeRevision
	}
	if os.Rename(temp, path) != nil || syncDirectory(s.root()) != nil {
		return ErrRuntimeRevision
	}
	return nil
}
func (s *revisionStore) restore(ctx context.Context, previous *runtimeRevision) error {
	if previous != nil {
		return s.activate(ctx, previous.id)
	}
	if ctx.Err() != nil {
		return ErrRuntimeRevision
	}
	path := filepath.Join(s.root(), "current")
	link, err := os.Readlink(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return ErrRuntimeRevision
	}
	id := filepath.Base(link)
	if link != filepath.Join("revisions", id) || !materialDigest.MatchString(id) {
		return ErrRuntimeRevision
	}
	if os.Remove(path) != nil || syncDirectory(s.root()) != nil {
		return ErrRuntimeRevision
	}
	return nil
}
