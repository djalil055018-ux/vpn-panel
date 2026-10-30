package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

const incidentColumns = `id::text,rule,resource,resource_name,severity,observed_since,last_observed_at,opened_at,resolved_at,acknowledged_at`

func scanIncident(row pgx.Row) (model.MonitoringIncident, error) {
	var i model.MonitoringIncident
	err := row.Scan(&i.ID, &i.Rule, &i.Resource, &i.ResourceName, &i.Severity, &i.ObservedSince, &i.LastObservedAt, &i.OpenedAt, &i.ResolvedAt, &i.AcknowledgedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return i, err
}
func (p *Postgres) SyncMonitoringIncidents(ctx context.Context, observations []model.IncidentObservation, at time.Time) error {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return ErrNotFound
	}
	if at.IsZero() {
		return errors.New("invalid scan time")
	}
	seen := map[string]bool{}
	for _, o := range observations {
		key := o.Rule + ":" + o.Resource
		if seen[key] || o.Rule == "" || o.Resource == "" || o.GraceSeconds < 0 || o.GraceSeconds > 3600 || (o.Severity != "warning" && o.Severity != "critical") {
			return errors.New("invalid observation")
		}
		seen[key] = true
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103505,1)`); err != nil {
		return err
	}
	var last time.Time
	err = tx.QueryRow(ctx, `SELECT last_success_at FROM monitoring_runs WHERE id=true`).Scan(&last)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && !at.After(last) {
		return tx.Commit(ctx)
	}
	active := []string{}
	for _, o := range observations {
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO monitoring_incidents(rule,resource,resource_name,severity,observed_since,last_observed_at) VALUES($1,$2,$3,$4,$5,$5)
   ON CONFLICT(rule,resource) WHERE resolved_at IS NULL DO UPDATE SET resource_name=excluded.resource_name,severity=excluded.severity,
   acknowledged_at=CASE WHEN monitoring_incidents.severity='warning' AND excluded.severity='critical' THEN NULL ELSE monitoring_incidents.acknowledged_at END,
   observed_since=CASE WHEN monitoring_incidents.opened_at IS NULL AND monitoring_incidents.last_observed_at<$5::timestamptz-interval '150 seconds' THEN $5 ELSE monitoring_incidents.observed_since END,
   last_observed_at=$5 RETURNING id::text`, o.Rule, o.Resource, o.ResourceName, o.Severity, at).Scan(&id)
		if err != nil {
			return err
		}
		active = append(active, id)
		if _, err = tx.Exec(ctx, `UPDATE monitoring_incidents SET opened_at=$2 WHERE id=$1::uuid AND opened_at IS NULL AND observed_since<=$2::timestamptz-($3::integer * interval '1 second')`, id, at, o.GraceSeconds); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM monitoring_incidents WHERE resolved_at IS NULL AND opened_at IS NULL AND NOT(id=ANY($1::uuid[]))`, active); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE monitoring_incidents SET resolved_at=$2 WHERE resolved_at IS NULL AND opened_at IS NOT NULL AND NOT(id=ANY($1::uuid[]))`, active, at); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM monitoring_incidents WHERE resolved_at<$1::timestamptz-interval '90 days'`, at); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO monitoring_runs(id,last_success_at) VALUES(true,$1) ON CONFLICT(id) DO UPDATE SET last_success_at=excluded.last_success_at`, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (p *Postgres) MonitoringStatus(ctx context.Context) (model.MonitoringStatus, error) {
	out := model.MonitoringStatus{GeneratedAt: time.Now().UTC(), Incidents: []model.MonitoringIncident{}}
	if _, scoped := TenantPrincipal(ctx); scoped {
		return out, ErrNotFound
	}
	err := p.Pool.QueryRow(ctx, `SELECT last_success_at FROM monitoring_runs WHERE id=true`).Scan(&out.LastSuccessAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if err = p.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE severity='critical') FROM monitoring_incidents WHERE opened_at IS NOT NULL AND resolved_at IS NULL`).Scan(&out.OpenCount, &out.CriticalCount); err != nil {
		return out, err
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+incidentColumns+` FROM monitoring_incidents WHERE opened_at IS NOT NULL ORDER BY (resolved_at IS NULL) DESC,(severity='critical') DESC,opened_at DESC,id LIMIT 200`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return out, err
		}
		out.Incidents = append(out.Incidents, i)
	}
	return out, rows.Err()
}
func (p *Postgres) AcknowledgeMonitoringIncident(ctx context.Context, id string) (model.MonitoringIncident, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return model.MonitoringIncident{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.MonitoringIncident{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	i, err := scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM monitoring_incidents WHERE id=$1::uuid AND opened_at IS NOT NULL AND resolved_at IS NULL FOR UPDATE`, id))
	if err != nil {
		return i, err
	}
	if i.AcknowledgedAt != nil {
		return i, tx.Commit(ctx)
	}
	i, err = scanIncident(tx.QueryRow(ctx, `UPDATE monitoring_incidents SET acknowledged_at=now() WHERE id=$1::uuid RETURNING `+incidentColumns, id))
	if err != nil {
		return i, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload) VALUES('monitoring.incident_acknowledged','admin','control-plane',jsonb_build_object('incident_id',$1::text))`, id)
	if err != nil {
		return i, err
	}
	return i, tx.Commit(ctx)
}
