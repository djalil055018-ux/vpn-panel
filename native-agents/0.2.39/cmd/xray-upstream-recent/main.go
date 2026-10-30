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
			60*time.Second,
		)

	defer cancel()

	client :=
		upstreamxray.NewClient()

	releases, err :=
		client.RecentLinuxAMD64(
			ctx,
			10,
		)

	if err != nil {
		log.Fatal(err)
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
			releases,
		); err != nil {

		log.Fatal(err)
	}
}
