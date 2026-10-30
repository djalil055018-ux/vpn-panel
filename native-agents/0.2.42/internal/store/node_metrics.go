package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

func saveNodeMetrics(ctx context.Context, tx pgx.Tx, nodeID string, metrics *model.NodeMetrics) error {
	if metrics == nil {
		return nil
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO node_metric_samples(
			node_id,sample_bucket,sampled_at,cpu_percent,load_1,
			memory_total_bytes,memory_used_bytes,disk_total_bytes,disk_used_bytes,
			network_rx_bytes,network_tx_bytes,uptime_seconds
		) VALUES(
			$1::uuid,floor(extract(epoch FROM now())/60)::bigint,now(),$2,$3,$4,$5,$6,$7,$8,$9,$10
		)
		ON CONFLICT(node_id,sample_bucket) DO UPDATE SET
			sampled_at=EXCLUDED.sampled_at,cpu_percent=EXCLUDED.cpu_percent,load_1=EXCLUDED.load_1,
			memory_total_bytes=EXCLUDED.memory_total_bytes,memory_used_bytes=EXCLUDED.memory_used_bytes,
			disk_total_bytes=EXCLUDED.disk_total_bytes,disk_used_bytes=EXCLUDED.disk_used_bytes,
			network_rx_bytes=EXCLUDED.network_rx_bytes,network_tx_bytes=EXCLUDED.network_tx_bytes,
			uptime_seconds=EXCLUDED.uptime_seconds`,
		nodeID, metrics.CPUPercent, metrics.Load1, metrics.MemoryTotal, metrics.MemoryUsed,
		metrics.DiskTotal, metrics.DiskUsed, metrics.NetworkRX, metrics.NetworkTX, metrics.UptimeSeconds)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM node_metric_samples WHERE node_id=$1::uuid AND sampled_at<now()-interval '31 days'`, nodeID)
	return err
}

func (p *Postgres) ListNodeMetrics(ctx context.Context, nodeID string, from, to time.Time, stepSeconds int) (model.NodeMetricSeries, error) {
	series := model.NodeMetricSeries{NodeID: nodeID, From: from, To: to, StepSeconds: stepSeconds, Points: []model.NodeMetricPoint{}}
	if _, scoped := TenantPrincipal(ctx); scoped {
		return series, ErrNotFound
	}
	var exists bool
	if err := p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1::uuid)`, nodeID).Scan(&exists); err != nil {
		return series, err
	}
	if !exists {
		return series, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `
		SELECT to_timestamp(floor(extract(epoch FROM sampled_at)/$4)*$4) AS bucket,
			avg(cpu_percent),avg(load_1),avg(memory_total_bytes)::bigint,avg(memory_used_bytes)::bigint,
			avg(disk_total_bytes)::bigint,avg(disk_used_bytes)::bigint,
			max(network_rx_bytes),max(network_tx_bytes),max(uptime_seconds)
		FROM node_metric_samples
		WHERE node_id=$1::uuid AND sampled_at>=$2 AND sampled_at<=$3
		GROUP BY bucket ORDER BY bucket LIMIT 2000`, nodeID, from, to, stepSeconds)
	if err != nil {
		return series, err
	}
	defer rows.Close()
	for rows.Next() {
		var point model.NodeMetricPoint
		if err = rows.Scan(&point.SampledAt, &point.CPUPercent, &point.Load1, &point.MemoryTotal, &point.MemoryUsed, &point.DiskTotal, &point.DiskUsed, &point.NetworkRX, &point.NetworkTX, &point.UptimeSeconds); err != nil {
			return series, err
		}
		series.Points = append(series.Points, point)
	}
	if err = rows.Err(); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return series, err
	}
	return series, nil
}
