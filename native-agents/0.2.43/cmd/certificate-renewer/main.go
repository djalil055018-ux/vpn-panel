package main

import (
	"context"
	"fmt"
	"os"
	"time"
	"vpn-platform/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, err := store.NewPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "certificate renewer database unavailable")
		os.Exit(1)
	}
	defer p.Close()
	count, err := p.QueueDueCertificateRenewals(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "certificate renewal scheduling failed")
		os.Exit(1)
	}
	fmt.Printf("certificate_renewals_queued=%d\n", count)
}
