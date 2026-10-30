package main

import (
	"context"
	"fmt"
	"os"
	"time"
	"vpn-platform/internal/monitoring"
	"vpn-platform/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "incident monitor database unavailable")
		os.Exit(1)
	}
	defer p.Close()
	snapshot, err := p.OperationsStatus(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "incident snapshot incomplete; previous incidents retained")
		os.Exit(1)
	}
	monitoring.AddLocalStatus(&snapshot)
	observations := monitoring.Evaluate(snapshot)
	if err = p.SyncMonitoringIncidents(ctx, observations, snapshot.GeneratedAt); err != nil {
		fmt.Fprintln(os.Stderr, "incident scan not committed; retry required")
		os.Exit(1)
	}
	fmt.Printf("monitoring_scan_complete observations=%d\n", len(observations))
}
