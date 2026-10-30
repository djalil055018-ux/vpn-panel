BEGIN;
CREATE TABLE billing_offers (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 plan_id UUID NOT NULL,
 name TEXT NOT NULL CHECK(length(btrim(name)) BETWEEN 1 AND 200),
 amount_minor BIGINT NOT NULL CHECK(amount_minor BETWEEN 1 AND 1000000000000),
 currency TEXT NOT NULL CHECK(currency IN ('RUB','USD','EUR','PLN','SEK')),
 duration_days INTEGER NOT NULL CHECK(duration_days BETWEEN 1 AND 3650),
 enabled BOOLEAN NOT NULL DEFAULT true,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(id,tenant_id),
 FOREIGN KEY(plan_id,tenant_id) REFERENCES vpn_access_plans(id,tenant_id)
);
CREATE INDEX billing_offers_tenant_idx ON billing_offers(tenant_id,created_at);
CREATE TABLE billing_invoices (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 offer_id UUID NOT NULL,
 client_id UUID NOT NULL,
 plan_id UUID NOT NULL,
 offer_name TEXT NOT NULL,
 amount_minor BIGINT NOT NULL CHECK(amount_minor BETWEEN 1 AND 1000000000000),
 currency TEXT NOT NULL CHECK(currency IN ('RUB','USD','EUR','PLN','SEK')),
 duration_days INTEGER NOT NULL CHECK(duration_days BETWEEN 1 AND 3650),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','void')),
 idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
 payment_reference TEXT,
 payment_source TEXT,
 paid_at TIMESTAMPTZ,
 entitlement_expires_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,idempotency_key),
 FOREIGN KEY(offer_id,tenant_id) REFERENCES billing_offers(id,tenant_id),
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id),
 FOREIGN KEY(plan_id,tenant_id) REFERENCES vpn_access_plans(id,tenant_id),
 CHECK((status='paid')=(paid_at IS NOT NULL)),
 CHECK(status<>'paid' OR (payment_reference IS NOT NULL AND payment_source IS NOT NULL AND entitlement_expires_at IS NOT NULL))
);
CREATE INDEX billing_invoices_tenant_idx ON billing_invoices(tenant_id,created_at DESC);
CREATE UNIQUE INDEX billing_payment_reference_unique ON billing_invoices(payment_reference) WHERE status='paid';
CREATE TABLE billing_entitlements (
 tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 client_id UUID NOT NULL,
 plan_id UUID NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(client_id,plan_id),
 FOREIGN KEY(client_id,tenant_id) REFERENCES vpn_clients(id,tenant_id) ON DELETE CASCADE,
 FOREIGN KEY(plan_id,tenant_id) REFERENCES vpn_access_plans(id,tenant_id) ON DELETE CASCADE
);
CREATE INDEX billing_entitlements_expiry_idx ON billing_entitlements(expires_at);
CREATE TABLE billing_payment_events (
 event_id TEXT PRIMARY KEY CHECK(length(event_id) BETWEEN 8 AND 128),
 invoice_id UUID NOT NULL REFERENCES billing_invoices(id) ON DELETE CASCADE,
 payload_hash TEXT NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
 received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE VIEW vpn_effective_client_services AS
 SELECT tenant_id,client_id,service_id FROM vpn_client_services
 UNION
 SELECT cap.tenant_id,cap.client_id,aps.service_id
 FROM vpn_client_access_plans cap
 JOIN vpn_access_plans ap ON ap.id=cap.plan_id AND ap.tenant_id=cap.tenant_id
 JOIN vpn_access_plan_services aps ON aps.plan_id=cap.plan_id AND aps.tenant_id=cap.tenant_id
 WHERE ap.enabled
 UNION
 SELECT be.tenant_id,be.client_id,aps.service_id
 FROM billing_entitlements be
 JOIN vpn_access_plans ap ON ap.id=be.plan_id AND ap.tenant_id=be.tenant_id
 JOIN vpn_access_plan_services aps ON aps.plan_id=be.plan_id AND aps.tenant_id=be.tenant_id
 WHERE ap.enabled AND be.expires_at>now();
COMMIT;
