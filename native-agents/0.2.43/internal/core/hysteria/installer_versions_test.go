package hysteria

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/model"
)

func TestInstallerLegacyAndCurrentCachesStayIndependent(t *testing.T) {
	latestBytes := testELF(62)
	legacyBytes := append(append([]byte{}, latestBytes...), []byte("legacy-fixture")...)
	requests := 0
	i, latest := testInstaller(t, latestBytes, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/legacy" {
			_, _ = w.Write(legacyBytes)
		} else {
			_, _ = w.Write(latestBytes)
		}
	}))
	original := i.pin
	sum := sha256.Sum256(legacyBytes)
	i.legacyPin = &artifactPin{model.HysteriaLegacyVersion, hex.EncodeToString(sum[:]), latest.DownloadURL + "/legacy", int64(len(legacyBytes))}
	legacy := model.CoreRelease{Type: "hysteria2", Version: i.legacyPin.version, SHA256: i.legacyPin.sha256, DownloadURL: i.legacyPin.url}
	legacyPath, err := i.Install(context.Background(), legacy)
	if err != nil || i.pin != original {
		t.Fatal("legacy installation altered the current installer selection")
	}
	latestPath, err := i.Install(context.Background(), latest)
	if err != nil || legacyPath == latestPath || filepath.Base(filepath.Dir(legacyPath)) != model.HysteriaLegacyVersion || filepath.Base(filepath.Dir(latestPath)) != PinnedVersion {
		t.Fatal("reviewed version paths were aliased")
	}
	for path, want := range map[string][]byte{legacyPath: legacyBytes, latestPath: latestBytes} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatal("one reviewed version overwrote another cache")
		}
	}
	for _, release := range []model.CoreRelease{legacy, latest} {
		if _, err := i.Install(context.Background(), release); err != nil {
			t.Fatal("verified version was not idempotent")
		}
	}
	broken := legacy
	broken.SHA256 = latest.SHA256
	if _, err := i.Install(context.Background(), broken); err == nil || requests != 2 {
		t.Fatal("mixed metadata reached the network or a corrupt cache")
	}
}
