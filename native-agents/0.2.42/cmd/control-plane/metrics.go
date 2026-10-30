package main

import (
	"errors"
	"math"
	"net/http"
	"regexp"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

var trafficEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validTrafficSnapshot(value *model.ClientTrafficSnapshot) bool {
	return value == nil || (trafficEpochPattern.MatchString(value.Epoch) && value.Epoch != "00000000000000000000000000000000" && value.Sequence > 0 && value.Sequence <= 9000000000000000 && validClientTraffic(value.Clients))
}

func validNodeMetrics(metrics *model.NodeMetrics) bool {
	if metrics == nil {
		return true
	}
	return !math.IsNaN(metrics.CPUPercent) && !math.IsInf(metrics.CPUPercent, 0) && metrics.CPUPercent >= 0 && metrics.CPUPercent <= 100 &&
		!math.IsNaN(metrics.Load1) && !math.IsInf(metrics.Load1, 0) && metrics.Load1 >= 0 && metrics.Load1 <= 1000000 &&
		metrics.MemoryTotal >= 0 && metrics.MemoryUsed >= 0 && metrics.MemoryUsed <= metrics.MemoryTotal &&
		metrics.DiskTotal >= 0 && metrics.DiskUsed >= 0 && metrics.DiskUsed <= metrics.DiskTotal &&
		metrics.NetworkRX >= 0 && metrics.NetworkTX >= 0 && metrics.UptimeSeconds >= 0
}

func validClientTraffic(samples []model.ClientTraffic) bool {
	if len(samples) > 10000 {
		return false
	}
	seen := make(map[string]struct{}, len(samples))
	for _, sample := range samples {
		if !accessPlanUUID.MatchString(sample.ClientID) || sample.Uplink < 0 || sample.Uplink > 9000000000000000 || sample.Downlink < 0 || sample.Downlink > 9000000000000000 || sample.ActiveIPs < 0 || sample.ActiveIPs > 10000 || (sample.ActiveIPsUnavailable && sample.ActiveIPs != 0) {
			return false
		}
		if _, exists := seen[sample.ClientID]; exists {
			return false
		}
		seen[sample.ClientID] = struct{}{}
	}
	return true
}

func metricWindow(value string, now time.Time) (time.Time, int, bool) {
	switch value {
	case "", "24h":
		return now.Add(-24 * time.Hour), 300, true
	case "1h":
		return now.Add(-time.Hour), 60, true
	case "7d":
		return now.Add(-7 * 24 * time.Hour), 1800, true
	case "30d":
		return now.Add(-30 * 24 * time.Hour), 7200, true
	default:
		return time.Time{}, 0, false
	}
}

func (a *application) nodeMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	nodeID := r.PathValue("id")
	if !accessPlanUUID.MatchString(nodeID) {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	now := time.Now().UTC()
	from, step, ok := metricWindow(r.URL.Query().Get("range"), now)
	if !ok {
		writeError(w, http.StatusBadRequest, "range must be 1h, 24h, 7d or 30d")
		return
	}
	series, err := a.store.ListNodeMetrics(r.Context(), nodeID, from, now, step)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "metrics unavailable")
		return
	}
	writeJSON(w, http.StatusOK, series)
}

func (a *application) registerMetricsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/nodes/{id}/metrics", a.requireAdmin(a.nodeMetrics))
}
