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

type sweepSummary struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Swept   int    `json:"swept"`
	Batches int    `json:"batches"`
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
		sweepSummary{
			Service: "vpn-platform-rollout-sweeper",

			Version: version,
		}

	for {
		plans, err :=
			db.SweepExpiredRolloutPlans(
				ctx,
				batchSize,
			)

		if err != nil {
			log.Fatalf(
				"sweep expired rollout plans: %v",
				err,
			)
		}

		if len(plans) == 0 {
			break
		}

		summary.Batches++
		summary.Swept += len(plans)

		for _, plan := range plans {

			log.Printf(
				"plan=%s node=%s previous_status=%s expired_at=%s marked=stale",
				plan.ID,
				plan.NodeID,
				plan.PreviousStatus,
				plan.ExpiresAt.UTC().Format(
					time.RFC3339,
				),
			)
		}

		if len(plans) < batchSize {
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
