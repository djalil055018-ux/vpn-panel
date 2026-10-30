BEGIN;
CREATE TABLE webhook_endpoints (
 id UUID PRIMARY KEY,
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
 url TEXT NOT NULL CHECK(length(url)<=1000),
 events TEXT[] NOT NULL CHECK(cardinality(events) BETWEEN 1 AND 2 AND events <@ ARRAY['billing.invoice_paid','billing.invoice_voided']::text[]),
 enabled BOOLEAN NOT NULL DEFAULT false,
 secret_ciphertext TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoints_tenant_idx ON webhook_endpoints(tenant_id);
CREATE TABLE webhook_deliveries (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
 event_id UUID NOT NULL,
 event_type TEXT NOT NULL,
 payload JSONB NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivering','delivered','failed','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 lease_until TIMESTAMPTZ,
 lease_token UUID,
 last_http_status INTEGER,
 last_error TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 completed_at TIMESTAMPTZ,
 UNIQUE(endpoint_id,event_id)
);
CREATE INDEX webhook_deliveries_queue_idx ON webhook_deliveries(next_attempt_at) WHERE status IN ('pending','delivering');
CREATE FUNCTION enqueue_billing_webhook() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE body JSONB;
BEGIN
 IF NEW.event_type NOT IN ('billing.invoice_paid','billing.invoice_voided') THEN RETURN NEW; END IF;
 SELECT jsonb_build_object('id',NEW.id,'type',NEW.event_type,'tenant_id',NEW.tenant_id,'created_at',NEW.created_at,'data',
  jsonb_build_object('invoice_id',i.id,'client_id',i.client_id,'plan_id',i.plan_id,'amount_minor',i.amount_minor,'currency',i.currency,'status',i.status,'duration_days',i.duration_days,'entitlement_expires_at',i.entitlement_expires_at))
 INTO body FROM billing_invoices i WHERE i.id::text=NEW.payload->>'invoice_id' AND i.tenant_id=NEW.tenant_id;
 IF body IS NULL THEN RAISE EXCEPTION 'billing webhook invoice snapshot unavailable'; END IF;
 INSERT INTO webhook_deliveries(endpoint_id,event_id,event_type,payload)
 SELECT id,NEW.id,NEW.event_type,body FROM webhook_endpoints WHERE tenant_id=NEW.tenant_id AND enabled AND NEW.event_type=ANY(events);
 RETURN NEW;
END;
$$;
CREATE TRIGGER billing_webhook_outbox AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION enqueue_billing_webhook();
COMMIT;
