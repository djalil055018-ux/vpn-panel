package monitoring

import (
	"time"
	"vpn-platform/internal/model"
)

func Evaluate(s model.OperationsStatus) []model.IncidentObservation {
	out := []model.IncidentObservation{}
	add := func(rule, resource, name, severity string, grace int) {
		out = append(out, model.IncidentObservation{Rule: rule, Resource: resource, ResourceName: name, Severity: severity, GraceSeconds: grace})
	}
	backup := func(resource, name string, b *model.BackupStatus) {
		if b != nil && b.Status == "failed" {
			add("backup_failed", resource, name, "critical", 0)
			return
		}
		if b == nil || b.LastSuccessAt == nil || b.LastVerifiedAt == nil {
			add("backup_missing", resource, name, "warning", 0)
			return
		}
		if s.GeneratedAt.Sub(*b.LastSuccessAt) > 36*time.Hour || s.GeneratedAt.Sub(*b.LastVerifiedAt) > 36*time.Hour {
			add("backup_stale", resource, name, "warning", 0)
		}
	}
	backup("control-plane", "Сервер панели", s.ControlPlaneBackup)
	if s.ControlPlaneFreeBytes < 0 {
		add("disk_unknown", "control-plane", "Сервер панели", "warning", 120)
	} else if s.ControlPlaneFreeBytes < 1024*1024*1024 {
		add("disk_low", "control-plane", "Сервер панели", "critical", 0)
	}
	for _, n := range s.Nodes {
		if !n.Lifecycle.Registered {
			continue
		}
		if !n.Lifecycle.Online {
			add("node_offline", n.ID, n.Name, "critical", 60)
		} else if !n.Lifecycle.Healthy || !n.Lifecycle.HealthFresh {
			add("node_unhealthy", n.ID, n.Name, "critical", 120)
		}
		if n.Lifecycle.DesiredGeneration != n.Lifecycle.AppliedGeneration {
			add("node_not_converged", n.ID, n.Name, "warning", 300)
		}
		if delivery := n.TrafficDelivery; delivery != nil && n.Lifecycle.Online {
			if delivery.ReceivedAt == nil || delivery.RecordedAt == nil || s.GeneratedAt.Sub(*delivery.ReceivedAt) > 2*time.Minute || s.GeneratedAt.Sub(*delivery.RecordedAt) > 5*time.Minute {
				add("traffic_delivery_delayed", n.ID, n.Name, "warning", 120)
			}
		}
		backup(n.ID, n.Name, n.Backup)
		freshMetrics := n.Metrics != nil && s.GeneratedAt.Sub(n.Metrics.SampledAt) <= 2*time.Minute
		if freshMetrics {
			if n.Metrics.CPUPercent >= 95 {
				add("node_cpu_high", n.ID, n.Name, "warning", 600)
			}
			if n.Metrics.MemoryTotal > 0 && float64(n.Metrics.MemoryUsed)/float64(n.Metrics.MemoryTotal) >= .95 {
				add("node_memory_high", n.ID, n.Name, "warning", 300)
			}
			if n.Metrics.DiskTotal > 0 && n.Metrics.DiskTotal-n.Metrics.DiskUsed < 1024*1024*1024 {
				add("disk_low", n.ID, n.Name, "critical", 0)
			}
		}
		if n.Backup == nil || n.Backup.ReportedAt == nil || s.GeneratedAt.Sub(*n.Backup.ReportedAt) > 2*time.Hour {
			add("backup_report_stale", n.ID, n.Name, "warning", 0)
		} else if !freshMetrics && n.Backup.FreeBytes < 1024*1024*1024 {
			add("disk_low", n.ID, n.Name, "critical", 0)
		}
	}
	if s.ExpiredCertificates > 0 {
		add("certificate_expired", "certificates", "Сертификаты", "critical", 0)
	}
	if s.FailedCertificates > 0 {
		add("certificate_failed", "certificates", "Сертификаты", "warning", 0)
	}
	if s.ExpiringCertificates > 0 {
		add("certificate_expiring", "certificates", "Сертификаты", "warning", 0)
	}
	if s.PendingAccessNodes > 0 {
		add("access_revocation_pending", "access", "Клиентский доступ", "critical", 120)
	}
	for _, client := range s.ClientDeviceWarnings {
		add("client_device_limit_exceeded", client.ClientID, client.ClientName, "warning", 120)
	}
	if q := s.WebhookQueue; q != nil && q.EnabledEndpoints > 0 {
		if q.LastDispatchAt == nil || s.GeneratedAt.Sub(*q.LastDispatchAt) > 90*time.Second {
			add("webhook_worker_stale", "webhooks", "Исходящие webhooks", "critical", 0)
		}
		if q.OverdueDeliveries > 0 {
			add("webhook_queue_stalled", "webhooks", "Исходящие webhooks", "warning", 120)
		}
		if q.FailedDeliveries > 0 {
			add("webhook_delivery_failed", "webhooks", "Исходящие webhooks", "warning", 0)
		}
	}
	return out
}
