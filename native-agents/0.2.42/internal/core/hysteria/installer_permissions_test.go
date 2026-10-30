package hysteria

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstallerArtifactDirectoriesSurviveRestrictiveUmaskAndRepairLegacyModes(
	t *testing.T,
) {
	const helper = "VPN_PLATFORM_HYSTERIA_UMASK_HELPER"

	if os.Getenv(helper) != "1" {
		command := exec.Command(
			os.Args[0],
			"-test.run=^TestInstallerArtifactDirectoriesSurviveRestrictiveUmaskAndRepairLegacyModes$",
		)

		command.Env = append(
			os.Environ(),
			helper+"=1",
		)

		output, err :=
			command.CombinedOutput()

		if err != nil {
			t.Fatalf(
				"isolated umask regression failed: %v\n%s",
				err,
				output,
			)
		}

		return
	}

	syscall.Umask(0077)

	raw := testELF(62)

	installer, release :=
		testInstaller(
			t,
			raw,
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					_ *http.Request,
				) {
					_, _ = w.Write(raw)
				},
			),
		)

	destination, err :=
		installer.Install(
			context.Background(),
			release,
		)

	if err != nil {
		t.Fatal(
			"install under umask 0077 failed:",
			err,
		)
	}

	directories := []string{
		filepath.Join(
			installer.base,
			"cores",
		),
		filepath.Join(
			installer.base,
			"cores",
			"hysteria2",
		),
		filepath.Dir(destination),
	}

	assertDirectories :=
		func() {
			t.Helper()

			for _, path := range directories {

				info, err :=
					os.Lstat(path)

				if err != nil {
					t.Fatal(err)
				}

				if !info.IsDir() ||
					info.Mode().Perm() != 0755 ||
					!ownedBy(
						info,
						os.Geteuid(),
						-1,
					) {

					t.Fatalf(
						"artifact directory not canonical: %s mode=%o",
						path,
						info.Mode().Perm(),
					)
				}
			}
		}

	assertDirectories()

	binary, err :=
		os.Lstat(destination)

	if err != nil ||
		!binary.Mode().IsRegular() ||
		binary.Mode().Perm() != 0555 {

		t.Fatal(
			"installed binary mode changed",
		)
	}

	// Reproduce the production bug left by the old installer:
	// secure root-owned directories exist, but restrictive umask
	// made them inaccessible to the managed runtime.
	for _, path := range directories {

		if err :=
			os.Chmod(
				path,
				0700,
			); err != nil {

			t.Fatal(err)
		}
	}

	if _, err =
		installer.Install(
			context.Background(),
			release,
		); err != nil {

		t.Fatal(
			"legacy 0700 artifact directories were not repaired:",
			err,
		)
	}

	assertDirectories()
}
