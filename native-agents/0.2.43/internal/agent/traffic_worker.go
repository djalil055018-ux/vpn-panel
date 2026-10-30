package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
	"vpn-platform/internal/model"
)

func (c *Client) SendTrafficDelivery(ctx context.Context, token string, value model.TrafficDelivery) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/agent/traffic", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("traffic transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("traffic delivery rejected: HTTP %d", response.StatusCode)
	}
	return nil
}

type TrafficWorker struct {
	outbox            *TrafficOutbox
	collect           func(context.Context, bool) (*model.TrafficDelivery, error)
	send              func(context.Context, model.TrafficDelivery) error
	logf              func(string, ...any)
	captureMu         sync.Mutex
	drainMu           sync.Mutex
	lastEnqueued      int64
	refreshAfterError bool
	statusMu          sync.Mutex
	lastLog           time.Time
}

func NewTrafficWorker(outbox *TrafficOutbox, client *Client, token string, logf func(string, ...any)) *TrafficWorker {
	return &TrafficWorker{outbox: outbox, collect: CollectTrafficDelivery, send: func(ctx context.Context, value model.TrafficDelivery) error {
		return client.SendTrafficDelivery(ctx, token, value)
	}, logf: logf}
}

// NewTrafficWorkerWithCollector keeps queue/delivery semantics common to all
// runtimes. The selected collector is immutable once the worker is constructed.
func NewTrafficWorkerWithCollector(outbox *TrafficOutbox, client *Client, token string, logf func(string, ...any), collector func(context.Context, bool) (*model.TrafficDelivery, error)) (*TrafficWorker, error) {
	if outbox == nil || client == nil || collector == nil {
		return nil, errors.New("runtime traffic worker dependencies are required")
	}
	worker := NewTrafficWorker(outbox, client, token, logf)
	worker.collect = collector
	return worker, nil
}

func (w *TrafficWorker) Capture(ctx context.Context, force bool) error {
	w.captureMu.Lock()
	defer w.captureMu.Unlock()
	unlock, err := lockTrafficCapture(ctx, w.outbox.directory)
	if err != nil {
		return err
	}
	defer unlock()
	value, err := w.collect(ctx, force || w.refreshAfterError)
	if err != nil {
		w.refreshAfterError = true
		return err
	}
	if value == nil {
		return nil
	}
	if value.Snapshot.Sequence <= w.lastEnqueued {
		return nil
	}
	if err = w.outbox.Put(*value); err != nil {
		w.refreshAfterError = true
		return err
	}
	w.refreshAfterError = false
	w.lastEnqueued = value.Snapshot.Sequence
	return nil
}

// CaptureTrafficToOutbox performs a local durable sample only. It makes no
// Control Plane request and is safe for a short-lived systemd ExecStop helper.
func CaptureTrafficToOutbox(ctx context.Context, outbox *TrafficOutbox, collector func(context.Context, bool) (*model.TrafficDelivery, error)) error {
	if outbox == nil || collector == nil {
		return ErrTrafficOutboxCorrupt
	}
	worker := &TrafficWorker{outbox: outbox, collect: collector}
	return worker.Capture(ctx, true)
}

// Only this serialized path sends queued samples. The file remains durable when
// the HTTP response is lost after server commit, and replay is safe on retry.
func (w *TrafficWorker) Drain(ctx context.Context, limit int) error {
	w.drainMu.Lock()
	defer w.drainMu.Unlock()
	for i := 0; i < limit; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := w.outbox.Peek()
		if err != nil {
			return err
		}
		if value == nil {
			return nil
		}
		sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = w.send(sendCtx, *value)
		cancel()
		if err != nil {
			return err
		}
		if err = w.outbox.Acknowledge(value.Snapshot.Sequence); err != nil {
			return err
		}
	}
	return nil
}

func (w *TrafficWorker) logProblem(stage string, err error) {
	if err == nil || w.logf == nil {
		return
	}
	w.statusMu.Lock()
	defer w.statusMu.Unlock()
	if time.Since(w.lastLog) < time.Minute {
		return
	}
	w.lastLog = time.Now()
	kind := "unavailable"
	if errors.Is(err, ErrTrafficOutboxFull) {
		kind = "queue_full"
	}
	if errors.Is(err, ErrTrafficOutboxCorrupt) {
		kind = "queue_requires_repair"
	}
	w.logf("traffic delivery stage=%s status=%s", stage, kind)
}

func (w *TrafficWorker) BeforeStop(ctx context.Context) {
	w.logProblem("before_runtime_stop", w.Capture(ctx, true))
}

func (w *TrafficWorker) runScheduledCapture(ctx context.Context, ticks <-chan time.Time) {
	for {
		// The ticker already limits sampling frequency. A collector's 30s cache
		// is timestamped after sampling, so consulting it at a 30s tick can skip
		// alternate polls. Scheduled captures must request current counters.
		w.logProblem("capture", w.Capture(ctx, true))
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}

func (w *TrafficWorker) Run(ctx context.Context) {
	// Collection has its own goroutine so a disconnected HTTP request cannot
	// prevent sampling the current runtime before an external restart.
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		timer := time.NewTicker(30 * time.Second)
		defer timer.Stop()
		w.runScheduledCapture(ctx, timer.C)
	}()
	defer func() { <-collected }()
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		w.logProblem("send", w.Drain(ctx, 16))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
