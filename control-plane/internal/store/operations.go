package store

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"vpn-platform/internal/model"
)

func durableTrafficAgent(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	numbers := [3]uint64{}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return false
		}
		numbers[i] = n
	}
	return numbers[0] > 0 || numbers[1] > 2 || (numbers[1] == 2 && numbers[2] >= 23)
}

func (p *Postgres) SaveNodeBackupReport(ctx context.Context, nodeID string, report model.BackupStatus) error {
	report.ReportedAt = nil
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = p.Pool.Exec(ctx, `INSERT INTO node_backup_reports(node_id,document) VALUES($1::uuid,$2::jsonb) ON CONFLICT(node_id) DO UPDATE SET document=EXCLUDED.document,reported_at=now()`, nodeID, raw)
	return err
}
func (p *Postgres) OperationsStatus(ctx context.Context) (model.OperationsStatus, error) {
	out := model.OperationsStatus{GeneratedAt: time.Now().UTC(), Nodes: []model.OperationsNode{}, ClientDeviceWarnings: []model.ClientDeviceUsage{}}
	nodes, err := p.ListNodes(ctx)
	if err != nil {
		return out, err
	}
	reports := map[string]*model.BackupStatus{}
	metrics := map[string]*model.NodeMetricPoint{}
	rows, err := p.Pool.Query(ctx, `SELECT node_id::text,document,reported_at FROM node_backup_reports`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var id string
		var raw []byte
		var at time.Time
		if err = rows.Scan(&id, &raw, &at); err != nil {
			rows.Close()
			return out, err
		}
		var report model.BackupStatus
		if err = json.Unmarshal(raw, &report); err != nil {
			rows.Close()
			return out, err
		}
		report.ReportedAt = &at
		reports[id] = &report
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	metricRows, err := p.Pool.Query(ctx, `SELECT DISTINCT ON(node_id) node_id::text,sampled_at,cpu_percent,load_1,memory_total_bytes,memory_used_bytes,disk_total_bytes,disk_used_bytes,network_rx_bytes,network_tx_bytes,uptime_seconds FROM node_metric_samples ORDER BY node_id,sampled_at DESC`)
	if err != nil {
		return out, err
	}
	for metricRows.Next() {
		var id string
		var point model.NodeMetricPoint
		if err = metricRows.Scan(&id, &point.SampledAt, &point.CPUPercent, &point.Load1, &point.MemoryTotal, &point.MemoryUsed, &point.DiskTotal, &point.DiskUsed, &point.NetworkRX, &point.NetworkTX, &point.UptimeSeconds); err != nil {
			metricRows.Close()
			return out, err
		}
		metrics[id] = &point
	}
	err = metricRows.Err()
	metricRows.Close()
	if err != nil {
		return out, err
	}
	for _, node := range nodes {
		life, err := p.NodeLifecycle(ctx, node.ID, out.GeneratedAt)
		if err != nil {
			return out, err
		}
		out.Nodes = append(out.Nodes, model.OperationsNode{ID: node.ID, Name: node.Name, Lifecycle: life, Backup: reports[node.ID], Metrics: metrics[node.ID]})
	}
	deliveryRows, err := p.Pool.Query(ctx, `SELECT node_id::text,sample_sequence,recorded_at,received_at FROM node_traffic_delivery`)
	if err != nil {
		return out, err
	}
	deliveries := map[string]*model.TrafficDeliveryReceipt{}
	for deliveryRows.Next() {
		var id string
		var value model.TrafficDeliveryReceipt
		if err = deliveryRows.Scan(&id, &value.Sequence, &value.RecordedAt, &value.ReceivedAt); err != nil {
			deliveryRows.Close()
			return out, err
		}
		deliveries[id] = &value
	}
	err = deliveryRows.Err()
	deliveryRows.Close()
	if err != nil {
		return out, err
	}
	for i := range out.Nodes {
		node := &out.Nodes[i]
		node.TrafficDelivery = deliveries[node.ID]
		if node.TrafficDelivery == nil && durableTrafficAgent(node.Lifecycle.AgentVersion) {
			node.TrafficDelivery = &model.TrafficDeliveryReceipt{}
		}
	}
	err = p.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE not_after>now() AND not_after<=now()+interval '30 days'),count(*) FILTER(WHERE not_after<=now()),count(*) FILTER(WHERE status='failed'),count(*) FILTER(WHERE not_after<=now()+interval '30 days' OR status='failed') FROM node_certificates WHERE environment='production' AND status<>'revoked' AND EXISTS(SELECT 1 FROM nodes WHERE id=node_certificates.node_id AND nodes.status<>'retired')`).Scan(&out.ExpiringCertificates, &out.ExpiredCertificates, &out.FailedCertificates, &out.AttentionCertificates)
	if err != nil {
		return out, err
	}
	err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n WHERE `+accessMismatchPredicate).Scan(&out.PendingAccessNodes)
	if err != nil {
		return out, err
	}
	deviceRows, err := p.Pool.Query(ctx, `SELECT c.id::text,c.name,LEAST(sum(cur.active_ips),2147483647)::integer,l.device_limit FROM vpn_clients c JOIN vpn_client_limits l ON l.client_id=c.id JOIN node_client_traffic_cursors cur ON cur.client_id=c.id AND cur.observed_at>now()-interval '2 minutes' WHERE l.device_limit>0 GROUP BY c.id,c.name,l.device_limit HAVING bool_and(cur.active_ips_known) AND sum(cur.active_ips)>l.device_limit ORDER BY c.id`)
	if err != nil {
		return out, err
	}
	for deviceRows.Next() {
		var item model.ClientDeviceUsage
		if err = deviceRows.Scan(&item.ClientID, &item.ClientName, &item.ActiveIPs, &item.DeviceLimit); err != nil {
			deviceRows.Close()
			return out, err
		}
		out.ClientDeviceWarnings = append(out.ClientDeviceWarnings, item)
	}
	err = deviceRows.Err()
	deviceRows.Close()
	if err != nil {
		return out, err
	}
	queue, err := p.WebhookQueueStatus(ctx)
	if err == nil {
		out.WebhookQueue = &queue
	}
	return out, err
}
