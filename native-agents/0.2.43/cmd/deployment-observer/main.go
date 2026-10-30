package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"vpn-platform/internal/store"
)

const (
	batchSize = 100
	version   = "0.1.0"
)

type observerSummary struct {
	Service  string `json:"service"`
	Version  string `json:"version"`
	Detected int    `json:"detected"`
	Batches  int    `json:"batches"`
}

func main() {
	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			2*time.Minute,
		)

	defer cancel()

	db, err :=
		store.NewPostgres(
			ctx,
			mustEnv("DATABASE_URL"),
		)

	if err != nil {
		log.Fatalf(
			"connect PostgreSQL: %v",
			err,
		)
	}

	defer db.Close()

	summary :=
		observerSummary{
			Service: "vpn-platform-deployment-observer",
			Version: version,
		}

	for {
		observedAt :=
			time.Now().UTC()

		items, err :=
			db.DetectStuckDeployments(
				ctx,
				batchSize,
				observedAt,
			)

		if err != nil {
			log.Fatalf(
				"detect stuck deployments: %v",
				err,
			)
		}

		if len(items) == 0 {
			break
		}

		summary.Batches++
		summary.Detected += len(items)

		for _, item := range items {

			log.Printf(
				"deployment=%s node=%s generation=%d status=%s operational_state=%s age_seconds=%d node_online=%t",
				item.DeploymentID,
				item.NodeID,
				item.Generation,
				item.Status,
				item.OperationalState,
				item.AgeSeconds,
				item.NodeOnline,
			)
		}

		if len(items) < batchSize {
			break
		}
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
