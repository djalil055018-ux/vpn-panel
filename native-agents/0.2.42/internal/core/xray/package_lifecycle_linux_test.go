//go:build linux

package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

// All service-manager calls are mapped to a unique transient fixture unit.
// Driver.Init is deliberately excluded: no host user or production unit edits.
func TestApprovedPackageNativeUpgradeAndRollback(t *testing.T) {
	if os.Getenv("PAUK_XRAY_PROCESS_FIXTURE") != "1" {
		t.Skip("explicit isolated process fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root fixture required")
	}
	if _, err := user.LookupGroup("vpnplatform-xray"); err != nil {
		t.Fatal("existing runtime group required")
	}
	base := t.TempDir()
	d := New(base)
	for _, path := range []string{d.xrayDir(), d.coresDir(), d.snapshotDir()} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	shim := os.Getenv("PAUK_XRAY_SYSTEMCTL_SHIM")
	raw, err := os.ReadFile(shim)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "shim")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), raw, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("PAUK_FIXTURE_BASE", base)
	t.Cleanup(func() {
		if out, err := exec.Command(filepath.Join(bin, "systemctl"), "fixture-cleanup").CombinedOutput(); err != nil {
			t.Errorf("fixture cleanup: %s: %v", out, err)
		}
	})
	archives := map[string][]byte{}
	for version, env := range map[string]string{"26.9.9": "PAUK_XRAY_APPROVED_ARCHIVE", "26.9.30": "PAUK_XRAY_NEXT_ARCHIVE"} {
		b, err := os.ReadFile(os.Getenv(env))
		if err != nil {
			t.Fatal(err)
		}
		archives[version] = b
	}
	downloads := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := archives[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			_, _ = w.Write(b)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer downloads.Close()
	release := func(version string) model.CoreRelease {
		sum := sha256.Sum256(archives[version])
		return model.CoreRelease{Type: "xray", Version: version, DownloadURL: downloads.URL + "/" + version, SHA256: hex.EncodeToString(sum[:])}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("pauk-native-package-lifecycle")) }))
	defer origin.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := []byte(fmt.Sprintf(`{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"http","settings":{}}],"outbounds":[{"tag":"DIRECT","protocol":"freedom"},{"tag":"BLOCK","protocol":"blackhole"}],"routing":{"rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"DIRECT"},{"type":"field","domain":["geosite:private"],"outboundTag":"DIRECT"}]}}`, port))
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := origin.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	check := func(version string) string {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			res, e := client.Get(origin.URL)
			if e == nil {
				b, e := io.ReadAll(res.Body)
				res.Body.Close()
				if e == nil && res.StatusCode == 200 && string(b) == "pauk-native-package-lifecycle" {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("verified HTTPS through native process failed", version, e)
			}
			time.Sleep(100 * time.Millisecond)
		}
		transport.CloseIdleConnections()
		out, err := exec.Command(filepath.Join(bin, "systemctl"), "fixture-observe").Output()
		if err != nil {
			t.Fatal("process observation", err)
		}
		var observed struct {
			Binary string `json:"binary"`
			PID    string `json:"pid"`
		}
		if json.Unmarshal(out, &observed) != nil {
			t.Fatal("observation format")
		}
		if observed.Binary != d.binary(version) || observed.PID == "0" || d.CurrentVersion() != version {
			t.Fatal("wrong native process version")
		}
		return observed.PID
	}
	for _, version := range []string{"26.9.9", "26.9.30"} {
		if err := d.Install(ctx, release(version)); err != nil {
			t.Fatal("native package install", version, err)
		}
		for _, name := range []string{"geoip.dat", "geosite.dat"} {
			info, err := os.Stat(filepath.Join(d.versionDir(version), name))
			if err != nil || info.Size() == 0 || info.Mode().Perm() != 0644 {
				t.Fatal("unreadable routing assets", version, name)
			}
		}
		if err := d.Validate(ctx, version, config); err != nil {
			t.Fatal("native config validation", version, err)
		}
	}
	if err := d.ApplyConfig(config); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate("26.9.9"); err != nil {
		t.Fatal(err)
	}
	if err := d.StartContext(ctx); err != nil {
		t.Fatal(err)
	}
	first := check("26.9.9")
	snapshot, err := d.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	bad := release("26.9.30")
	bad.Version = "checksum-rejected"
	bad.SHA256 = strings.Repeat("0", 64)
	if d.Install(ctx, bad) == nil || d.Installed(bad.Version) || check("26.9.9") != first {
		t.Fatal("rejected package changed active runtime")
	}
	invalid := []byte(`{"routing":{"rules":[{"type":"field","domain":["geosite:pauk_missing_category"],"outboundTag":"DIRECT"}]},"outbounds":[{"tag":"DIRECT","protocol":"freedom"}]}`)
	if d.Validate(ctx, "26.9.30", invalid) == nil || check("26.9.9") != first {
		t.Fatal("invalid routing mutated active runtime")
	}
	if err := d.StopContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Activate("26.9.30"); err != nil {
		t.Fatal(err)
	}
	if err := d.StartContext(ctx); err != nil {
		t.Fatal(err)
	}
	second := check("26.9.30")
	if second == first {
		t.Fatal("upgrade did not replace process")
	}
	if err := d.RollbackContext(ctx, snapshot); err != nil {
		t.Fatal("rollback", err)
	}
	third := check("26.9.9")
	if third == second {
		t.Fatal("rollback did not replace process")
	}
	restored, err := os.ReadFile(d.configPath())
	if err != nil || !bytes.Equal(restored, config) {
		t.Fatal("rollback configuration mismatch")
	}
	t.Log("real packages: 26.9.9 -> 26.9.30 -> 26.9.9; verified HTTPS at each step; checksum and routing rejection preserve original process")
}
