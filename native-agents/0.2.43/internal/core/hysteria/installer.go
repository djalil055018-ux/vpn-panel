package hysteria

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"vpn-platform/internal/model"
)

var ErrArtifact = errors.New("Hysteria artifact is unsupported, unavailable or invalid")

const PinnedVersion = model.HysteriaPinnedVersion
const PinnedSHA256 = model.HysteriaPinnedSHA256
const PinnedDownloadURL = model.HysteriaPinnedDownloadURL
const pinnedSize int64 = 23924898
const legacyPinnedSize int64 = 23224482

type artifactPin struct {
	version, sha256, url string
	size                 int64
}

// Installer only stages verified, immutable version files. It never activates a
// version, edits the running config, or replaces a corrupt existing installation.
// Only exact reviewed Linux/amd64 tuples are accepted. The legacy release remains
// available for existing nodes; registry metadata cannot authorize arbitrary code.
type Installer struct {
	base      string
	pin       artifactPin
	legacyPin *artifactPin
	client    *http.Client
}

func NewInstaller(base string) (*Installer, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, ErrArtifact
	}
	if err := protectedDirectory(base, false); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || r.URL.Scheme != "https" || r.URL.User != nil {
			return ErrArtifact
		}
		switch r.URL.Host {
		case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
			return nil
		default:
			return ErrArtifact
		}
	}}
	return &Installer{base: base, pin: artifactPin{PinnedVersion, PinnedSHA256, PinnedDownloadURL, pinnedSize}, legacyPin: &artifactPin{model.HysteriaLegacyVersion, model.HysteriaLegacySHA256, model.HysteriaLegacyDownloadURL, legacyPinnedSize}, client: client}, nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrArtifact
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrArtifact
	}
	return nil
}

func protectedDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err = os.Mkdir(path, 0755); err != nil && !os.IsExist(err) {
			return ErrArtifact
		}
		if err = syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !ownedBy(info, os.Geteuid(), -1) {
		return ErrArtifact
	}
	return nil
}

// artifactDirectory is intentionally traversable by the managed Hysteria
// identity. The platform data root remains group-gated, so making immutable
// core artifact directories 0755 does not expose private agent state.
//
// Explicit chmod is required because the node-agent runs with UMask=0077;
// relying on os.Mkdir(path, 0755) alone would otherwise create 0700
// directories and prevent the managed unprivileged runtime from executing
// the verified core artifact.
//
// Existing secure but overly restrictive directories are repaired. Writable,
// symlinked or non-root-owned directories are always rejected.
func artifactDirectory(path string) error {
	info, err := os.Lstat(path)

	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0755); err != nil && !os.IsExist(err) {
			return ErrArtifact
		}

		if err = syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}

		info, err = os.Lstat(path)
	}

	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0022 != 0 ||
		!ownedBy(info, os.Geteuid(), -1) {

		return ErrArtifact
	}

	if info.Mode().Perm() != 0755 {
		if err = os.Chmod(path, 0755); err != nil {
			return ErrArtifact
		}

		if err = syncDirectory(path); err != nil {
			return err
		}

		info, err = os.Lstat(path)

		if err != nil ||
			!info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0755 ||
			!ownedBy(info, os.Geteuid(), -1) {

			return ErrArtifact
		}
	}

	return nil
}

func (i *Installer) destination(release model.CoreRelease) (string, error) {
	if release.Type != "hysteria2" || release.Version != i.pin.version || release.SHA256 != i.pin.sha256 || release.DownloadURL != i.pin.url {
		return "", ErrArtifact
	}
	return filepath.Join(i.base, "cores", "hysteria2", i.pin.version, "hysteria"), nil
}

func (i *Installer) verify(ctx context.Context, path string) error {
	if ctx.Err() != nil {
		return ErrArtifact
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0555 || info.Size() != i.pin.size || !ownedBy(info, os.Geteuid(), -1) {
		return ErrArtifact
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrArtifact
	}
	defer f.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil || hex.EncodeToString(hash.Sum(nil)) != i.pin.sha256 {
		return ErrArtifact
	}
	binary, err := elf.NewFile(f)
	if err != nil {
		return ErrArtifact
	}
	if binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Machine != elf.EM_X86_64 || (binary.Type != elf.ET_EXEC && binary.Type != elf.ET_DYN) || ctx.Err() != nil {
		return ErrArtifact
	}
	return nil
}

func (i *Installer) forRelease(release model.CoreRelease) (*Installer, error) {
	matches := func(pin artifactPin) bool {
		return release.Type == "hysteria2" && release.Version == pin.version && release.SHA256 == pin.sha256 && release.DownloadURL == pin.url
	}
	if matches(i.pin) {
		return i, nil
	}
	if i.legacyPin != nil && matches(*i.legacyPin) {
		selected := *i
		selected.pin = *i.legacyPin
		selected.legacyPin = nil
		return &selected, nil
	}
	return nil, ErrArtifact
}

func (i *Installer) Install(ctx context.Context, release model.CoreRelease) (string, error) {
	selected, selectErr := i.forRelease(release)
	if selectErr != nil {
		return "", selectErr
	}
	if selected != i {
		return selected.Install(ctx, release)
	}
	destination, err := i.destination(release)
	if err != nil || ctx.Err() != nil {
		return "", ErrArtifact
	}
	if err = protectedDirectory(i.base, false); err != nil {
		return "", err
	}

	for _, path := range []string{
		filepath.Join(i.base, "cores"),
		filepath.Join(i.base, "cores", "hysteria2"),
		filepath.Dir(destination),
	} {
		if err = artifactDirectory(path); err != nil {
			return "", err
		}
	}
	if _, err = os.Lstat(destination); err == nil {
		if err = i.verify(ctx, destination); err != nil {
			return "", err
		}
		if err = syncDirectory(filepath.Dir(destination)); err != nil {
			return "", err
		}
		return destination, nil
	} else if !os.IsNotExist(err) {
		return "", ErrArtifact
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, i.pin.url, nil)
	if err != nil {
		return "", ErrArtifact
	}
	response, err := i.client.Do(request)
	if err != nil {
		return "", ErrArtifact
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.ContentLength >= 0 && response.ContentLength != i.pin.size) {
		return "", ErrArtifact
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".artifact-")
	if err != nil {
		return "", ErrArtifact
	}
	temp := file.Name()
	defer os.Remove(temp)
	count, copyErr := io.Copy(file, io.LimitReader(response.Body, i.pin.size+1))
	if copyErr != nil || count != i.pin.size || ctx.Err() != nil {
		file.Close()
		return "", ErrArtifact
	}
	if err = file.Chmod(0555); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return "", ErrArtifact
	}
	if err = i.verify(ctx, temp); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", ErrArtifact
	}
	if err = os.Link(temp, destination); err != nil {
		if !os.IsExist(err) || i.verify(ctx, destination) != nil {
			return "", ErrArtifact
		}
	}
	if err = syncDirectory(filepath.Dir(destination)); err != nil {
		return "", err
	}
	return destination, nil
}
