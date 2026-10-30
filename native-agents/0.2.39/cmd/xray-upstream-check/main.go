package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	upstreamxray "vpn-platform/internal/upstream/xray"
)

func main() {
	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			30*time.Second,
		)

	defer cancel()

	client :=
		upstreamxray.NewClient()

	release, err :=
		client.LatestLinuxAMD64(ctx)

	if err != nil {
		log.Fatal(err)
	}

	encoder :=
		json.NewEncoder(os.Stdout)

	encoder.SetIndent("", "  ")

	if err :=
		encoder.Encode(
			map[string]any{
				"version": release.Version,

				"download_url": release.DownloadURL,

				"sha256": release.SHA256,

				"upstream_prerelease": release.UpstreamPrerelease,

				"github_release_id": release.ReleaseID,

				"github_asset_id": release.AssetID,

				"asset_name": release.AssetName,

				"published_at": release.PublishedAt,
			},
		); err != nil {
		log.Fatal(err)
	}
}
