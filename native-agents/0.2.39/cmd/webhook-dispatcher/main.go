package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"vpn-platform/internal/store"
	"vpn-platform/internal/webhook"
)

func main() {
	master := os.Getenv("WEBHOOK_ENCRYPTION_KEY")
	if !webhook.MasterReady(master) {
		fmt.Fprintln(os.Stderr, "webhook encryption key unavailable")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "webhook database unavailable")
		os.Exit(1)
	}
	defer p.Close()
	deliveries, err := p.ClaimWebhooks(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "webhook queue unavailable")
		os.Exit(1)
	}
	client := webhook.NewHTTPClient()
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	var failures atomic.Int32
	for _, delivery := range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret, err := webhook.Decrypt(master, delivery.EndpointID, delivery.EncryptedSecret)
			status, category := 0, "key_unavailable"
			if err == nil {
				status, category = webhook.Send(ctx, client, delivery.URL, secret, delivery.EventID, delivery.ID, delivery.Payload)
			}
			finishCtx, finishCancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer finishCancel()
			if err = p.FinishWebhook(finishCtx, delivery, status, category); err != nil {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("webhook_batch_attempted=%d state_update_failures=%d\n", len(deliveries), failures.Load())
	if failures.Load() > 0 {
		os.Exit(1)
	}
	healthCtx, healthCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer healthCancel()
	if err = p.RecordWebhookDispatcherSuccess(healthCtx); err != nil {
		fmt.Fprintln(os.Stderr, "webhook worker health not recorded")
		os.Exit(1)
	}
}
