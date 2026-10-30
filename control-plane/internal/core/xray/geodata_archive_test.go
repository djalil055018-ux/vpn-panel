package xray

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type packageEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func packageFixture(t *testing.T, entries []packageEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release.zip")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	w := zip.NewWriter(f)
	for _, entry := range entries {
		h := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		h.SetMode(entry.mode)
		out, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = out.Write(entry.data); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	return path
}

func TestExtractXrayPackageRetainsRoutingAssets(t *testing.T) {
	entries := []packageEntry{{"xray", []byte("native binary"), 0755}, {"geoip.dat", []byte("geoip:private"), 0644}, {"geosite.dat", []byte("geosite:private"), 0644}, {"README.md", []byte("ignored"), 0644}}
	target := t.TempDir()
	if err := extractBinary(packageFixture(t, entries), target); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries[:3] {
		actual, e := os.ReadFile(filepath.Join(target, entry.name))
		if e != nil || !bytes.Equal(actual, entry.data) {
			t.Fatal("package contents changed or missing")
		}
		info, e := os.Stat(filepath.Join(target, entry.name))
		if e != nil || info.Mode().Perm() != entry.mode {
			t.Fatal("native runtime cannot read extracted package")
		}
	}
	files, e := os.ReadDir(target)
	if e != nil || len(files) != 3 {
		t.Fatal("unreviewed archive entry extracted")
	}
}

func TestExtractXrayPackageBinaryOnlyCompatibility(t *testing.T) {
	target := t.TempDir()
	if err := extractBinary(packageFixture(t, []packageEntry{{"xray", []byte("binary"), 0755}}), target); err != nil {
		t.Fatal(err)
	}
}

func TestExtractXrayPackageRefusesAmbiguousOrUnsafeEntries(t *testing.T) {
	binary := packageEntry{"xray", []byte("binary"), 0755}
	cases := map[string][]packageEntry{
		"duplicate_binary": {binary, binary},
		"duplicate_geoip":  {binary, {"geoip.dat", []byte("a"), 0644}, {"geoip.dat", []byte("b"), 0644}},
		"symlink_geoip":    {binary, {"geoip.dat", []byte("/etc/passwd"), os.ModeSymlink | 0777}},
		"empty_geosite":    {binary, {"geosite.dat", nil, 0644}},
		"no_binary":        {{"geoip.dat", []byte("a"), 0644}},
		"nested_binary":    {{"../xray", []byte("binary"), 0755}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			target := t.TempDir()
			if extractBinary(packageFixture(t, entries), target) == nil {
				t.Fatal("unsafe archive accepted")
			}
			files, e := os.ReadDir(target)
			if e != nil || len(files) != 0 {
				t.Fatal("invalid archive wrote partial files")
			}
		})
	}
}

func TestExtractXrayPackageRefusesOverwrite(t *testing.T) {
	target := t.TempDir()
	file := filepath.Join(target, "xray")
	if os.WriteFile(file, []byte("existing"), 0755) != nil {
		t.Fatal("fixture")
	}
	if extractBinary(packageFixture(t, []packageEntry{{"xray", []byte("replacement"), 0755}}), target) == nil {
		t.Fatal("existing native core overwritten")
	}
	actual, e := os.ReadFile(file)
	if e != nil || string(actual) != "existing" {
		t.Fatal("prior core changed")
	}
}

func TestExtractXrayPackageApprovedArtifactNativeGeodata(t *testing.T) {
	archive := os.Getenv("PAUK_XRAY_APPROVED_ARCHIVE")
	if archive == "" {
		t.Skip("approved archive supplied by owner fixture")
	}
	target := t.TempDir()
	if e := extractBinary(archive, target); e != nil {
		t.Fatal("approved package extraction failed")
	}
	raw, e := os.ReadFile(filepath.Join(target, "xray"))
	if e != nil {
		t.Fatal("native binary missing")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "c4ae6798c38e0e5343b192406746333cd0ba7ff3eb984f8c4b9939dcb68c3f8a" {
		t.Fatal("unreviewed native binary")
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		info, e := os.Stat(filepath.Join(target, name))
		if e != nil || info.Size() == 0 || info.Mode().Perm() != 0644 {
			t.Fatal("approved routing data unavailable")
		}
	}
	config := `{"inbounds":[],"outbounds":[{"tag":"DIRECT","protocol":"freedom"},{"tag":"BLOCK","protocol":"blackhole"}],"routing":{"rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"BLOCK"},{"type":"field","domain":["geosite:private"],"outboundTag":"BLOCK"}]}}`
	name := filepath.Join(target, "candidate.json")
	if os.WriteFile(name, []byte(config), 0600) != nil {
		t.Fatal("private config write failed")
	}
	cmd := exec.Command(filepath.Join(target, "xray"), "run", "-test", "-config", name)
	cmd.Dir = target
	output, e := cmd.CombinedOutput()
	if e != nil || !strings.Contains(string(output), "Configuration OK.") {
		t.Fatal("native parser cannot resolve shipped routing data")
	}
}
