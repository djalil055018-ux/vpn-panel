package store

import (
	"context"
	"errors"
	"vpn-platform/internal/model"
)

func (p *Postgres) AuditHistory(ctx context.Context, tenant, eventType, actorType string, cursor *model.AuditCursor, limit int) (model.AuditHistory, error) {
	out := model.AuditHistory{Events: []model.AuditEventMetadata{}}
	if _, scoped := TenantPrincipal(ctx); scoped {
		return out, ErrNotFound
	}
	if limit < 1 || limit > 100 {
		return out, errors.New("invalid audit limit")
	}
	var tenantArg, atArg, idArg any
	if tenant != "" {
		tenantArg = tenant
	}
	if cursor != nil {
		atArg = cursor.At
		idArg = cursor.ID
	}
	// Raw payloads and arbitrary actor IDs are intentionally excluded. Some old
	// records predate the current credential handling rules.
	rows, err := p.Pool.Query(ctx, `SELECT id::text,tenant_id::text,node_id::text,event_type,actor_type,CASE WHEN actor_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN actor_id ELSE NULL END,created_at,
 CASE WHEN event_type='admin_request.completed' AND payload->>'request_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN payload->>'request_id' END,
 CASE WHEN event_type='admin_request.completed' AND payload->>'outcome' IN ('responded','interrupted') THEN payload->>'outcome' END,
 CASE WHEN event_type='admin_request.completed' AND jsonb_typeof(payload->'http_status')='number' AND payload->>'http_status' ~ '^[2-5][0-9]{2}$' THEN (payload->>'http_status')::int END
 FROM audit_events
 WHERE ($1::uuid IS NULL OR tenant_id=$1::uuid) AND ($2='' OR event_type=$2) AND ($3='' OR actor_type=$3) AND ($4::timestamptz IS NULL OR (created_at,id)<($4::timestamptz,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT $6`, tenantArg, eventType, actorType, atArg, idArg, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var e model.AuditEventMetadata
		if err = rows.Scan(&e.ID, &e.TenantID, &e.NodeID, &e.EventType, &e.ActorType, &e.ActorID, &e.CreatedAt, &e.RequestID, &e.RequestOutcome, &e.HTTPStatus); err != nil {
			return out, err
		}
		if e.RequestID == nil || e.RequestOutcome == nil || (*e.RequestOutcome == "responded" && e.HTTPStatus == nil) || (*e.RequestOutcome == "interrupted" && e.HTTPStatus != nil) {
			e.RequestID, e.RequestOutcome, e.HTTPStatus = nil, nil, nil
		}
		out.Events = append(out.Events, e)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if len(out.Events) > limit {
		out.Events = out.Events[:limit]
		last := out.Events[len(out.Events)-1]
		out.NextCursor = &model.AuditCursor{At: last.CreatedAt, ID: last.ID}
	}
	return out, nil
}
func (p *Postgres) AuditEventTypes(ctx context.Context) ([]string, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT DISTINCT event_type FROM audit_events ORDER BY event_type LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}
