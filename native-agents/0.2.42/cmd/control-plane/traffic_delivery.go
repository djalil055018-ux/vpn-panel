package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"vpn-platform/internal/model"
)

func (a *application) receiveTrafficDelivery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	node := currentNode(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var delivery model.TrafficDelivery
	if decoder.Decode(&delivery) != nil || decoder.Decode(new(any)) != io.EOF || !validTrafficSnapshot(&delivery.Snapshot) || delivery.RecordedAt.IsZero() || delivery.RecordedAt.Year() < 2000 || delivery.RecordedAt.After(time.Now().Add(5*time.Minute)) {
		writeError(w, 400, "invalid traffic delivery")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := a.store.SaveTrafficDelivery(ctx, node.ID, delivery); err != nil {
		writeError(w, 503, "traffic delivery unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
