package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
	upstreamxray "vpn-platform/internal/upstream/xray"
)

type syncSummary struct {
	Core             string   `json:"core"`
	OS               string   `json:"os"`
	Architecture     string   `json:"architecture"`
	Discovered       int      `json:"discovered"`
	Imported         int      `json:"imported"`
	Unchanged        int      `json:"unchanged"`
	Conflicts        int      `json:"conflicts"`
	Errors           int      `json:"errors"`
	ImportedVersions []string `json:"imported_versions,omitempty"`
	ConflictVersions []string `json:"conflict_versions,omitempty"`
	ErrorVersions    []string `json:"error_versions,omitempty"`
}

func main() {
	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			3*time.Minute,
		)

	defer cancel()

	databaseURL :=
		mustEnv("DATABASE_URL")

	db, err :=
		store.NewPostgres(
			ctx,
			databaseURL,
		)

	if err != nil {
		log.Fatalf(
			"connect PostgreSQL: %v",
			err,
		)
	}

	defer db.Close()

	client :=
		upstreamxray.NewClient()

	releases, err :=
		client.RecentLinuxAMD64(
			ctx,
			20,
		)

	if err != nil {
		log.Fatalf(
			"discover Xray releases: %v",
			err,
		)
	}

	summary := syncSummary{
		Core:         "xray",
		OS:           "linux",
		Architecture: "amd64",
		Discovered:   len(releases),
	}

	for _, upstreamRelease := range releases {

		metadata := map[string]any{
			"source": "github",

			"repository": "XTLS/Xray-core",

			"github_release_id": upstreamRelease.ReleaseID,

			"github_asset_id": upstreamRelease.AssetID,

			"asset_name": upstreamRelease.AssetName,

			"published_at": upstreamRelease.PublishedAt,

			"importer": "vpn-platform-core-sync",

			"sync_mode": "upstream_recent",
		}

		metadataRaw, err :=
			json.Marshal(metadata)

		if err != nil {
			summary.Errors++
			summary.ErrorVersions =
				append(
					summary.ErrorVersions,
					upstreamRelease.Version,
				)

			log.Printf(
				"version=%s metadata error: %v",
				upstreamRelease.Version,
				err,
			)

			continue
		}

		_, created, err :=
			db.ImportCoreRelease(
				ctx,
				model.CoreReleaseRecord{
					Type: "xray",

					Version: upstreamRelease.Version,

					OS: "linux",

					Architecture: "amd64",

					DownloadURL: upstreamRelease.DownloadURL,

					SHA256: upstreamRelease.SHA256,

					Channel: "testing",

					UpstreamPrerelease: upstreamRelease.UpstreamPrerelease,
				},
				string(metadataRaw),
			)

		if errors.Is(
			err,
			store.ErrCoreReleaseIntegrityConflict,
		) {
			summary.Conflicts++
			summary.ConflictVersions =
				append(
					summary.ConflictVersions,
					upstreamRelease.Version,
				)

			log.Printf(
				"version=%s integrity conflict",
				upstreamRelease.Version,
			)

			continue
		}

		if err != nil {
			summary.Errors++
			summary.ErrorVersions =
				append(
					summary.ErrorVersions,
					upstreamRelease.Version,
				)

			log.Printf(
				"version=%s import error: %v",
				upstreamRelease.Version,
				err,
			)

			continue
		}

		if created {
			summary.Imported++
			summary.ImportedVersions =
				append(
					summary.ImportedVersions,
					upstreamRelease.Version,
				)

			log.Printf(
				"version=%s imported",
				upstreamRelease.Version,
			)

			continue
		}

		summary.Unchanged++

		log.Printf(
			"version=%s already present",
			upstreamRelease.Version,
		)
	}

	encoder :=
		json.NewEncoder(
			os.Stdout,
		)

	encoder.SetIndent(
		"",
		"  ",
	)

	if err :=
		encoder.Encode(
			summary,
		); err != nil {

		log.Fatal(err)
	}

	if summary.Conflicts > 0 ||
		summary.Errors > 0 {

		fmt.Fprintln(
			os.Stderr,
			"core sync completed with problems",
		)

		os.Exit(1)
	}
}

func mustEnv(
	key string,
) string {

	value :=
		os.Getenv(key)

	if value == "" {
		log.Fatalf(
			"required environment variable %s is not set",
			key,
		)
	}

	return value
}
