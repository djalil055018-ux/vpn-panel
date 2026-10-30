package xray

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRuntimeTestCore(
	t *testing.T,
	driver *Driver,
	version string,
) {
	t.Helper()

	if err := os.MkdirAll(
		driver.versionDir(version),
		0755,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		driver.binary(version),
		[]byte("xray"),
		0755,
	); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeTestSnapshot(
	t *testing.T,
	driver *Driver,
	id string,
	version string,
	config bool,
) {
	t.Helper()

	dir := filepath.Join(
		driver.snapshotDir(),
		id,
	)

	if err := os.MkdirAll(
		dir,
		0700,
	); err != nil {
		t.Fatal(err)
	}

	raw := []byte(
		`{"version":"` +
			version +
			`"}`,
	)

	if err := os.WriteFile(
		filepath.Join(dir, "metadata.json"),
		raw,
		0600,
	); err != nil {
		t.Fatal(err)
	}

	if config {
		if err := os.WriteFile(
			filepath.Join(dir, "config.json"),
			[]byte(`{}`),
			0600,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuntimeRecoveryInfoSelectsLatestValidSnapshot(
	t *testing.T,
) {
	driver := New(
		t.TempDir(),
	)

	writeRuntimeTestCore(
		t,
		driver,
		"26.7.28",
	)

	writeRuntimeTestSnapshot(
		t,
		driver,
		"100",
		"26.7.28",
		true,
	)

	writeRuntimeTestSnapshot(
		t,
		driver,
		"200",
		"missing",
		true,
	)

	writeRuntimeTestSnapshot(
		t,
		driver,
		"300",
		"26.7.28",
		false,
	)

	info := driver.RuntimeRecoveryInfo()

	if info.SnapshotCount != 3 {
		t.Fatalf(
			"snapshot_count=%d want=3",
			info.SnapshotCount,
		)
	}

	if info.LatestSnapshotID != "100" {
		t.Fatalf(
			"latest=%q want=100",
			info.LatestSnapshotID,
		)
	}

	if info.LastKnownGoodCoreVersion !=
		"26.7.28" {
		t.Fatalf(
			"lkg=%q want=26.7.28",
			info.LastKnownGoodCoreVersion,
		)
	}

	if !info.RollbackReady {
		t.Fatal(
			"rollback must be ready",
		)
	}
}
