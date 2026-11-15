--
-- PostgreSQL database dump
--


-- Dumped from database version 18.6
-- Dumped by pg_dump version 18.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pauk_native_cutover; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA pauk_native_cutover;


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: begin_capture(); Type: FUNCTION; Schema: pauk_native_cutover; Owner: -
--

CREATE FUNCTION pauk_native_cutover.begin_capture() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public', 'pauk_native_cutover'
    AS $$
DECLARE expected integer; actual integer;
BEGIN
 IF NEW.state<>'verifying' THEN RAISE EXCEPTION 'NATIVE_CAPTURE_REQUIRES_NEW_CUTOVER'; END IF;
 INSERT INTO pauk_native_cutover.sessions(import_id,tenant_id,request_sha256,inventory_sha256)
 VALUES(NEW.import_id,NEW.tenant_id,NEW.request_sha256,NEW.inventory_sha256);
 INSERT INTO pauk_native_cutover.nodes(import_id,node_id,source_node_id)
 SELECT NEW.import_id,p.node_id,p.source_node_id FROM node_xray_profiles p
 WHERE p.import_id=NEW.import_id AND p.tenant_id=NEW.tenant_id AND p.state='active';
 SELECT count(*) INTO actual FROM pauk_native_cutover.nodes WHERE import_id=NEW.import_id;
 expected:=jsonb_array_length(NEW.request->'nodes');
 IF actual=0 OR expected IS DISTINCT FROM actual OR EXISTS(
  SELECT 1 FROM node_client_traffic_cursors c JOIN pauk_native_cutover.nodes n ON n.node_id=c.node_id WHERE n.import_id=NEW.import_id
 ) THEN RAISE EXCEPTION 'NATIVE_CAPTURE_NODE_BASELINE_NOT_EMPTY'; END IF;
 INSERT INTO pauk_native_cutover.clients(import_id,client_id,source_user_id,credential_sha256,baseline_bytes,limit_bytes,expires_at,status)
 SELECT NEW.import_id,c.id,m.source_user_id,encode(sha256(convert_to(c.vless_uuid::text,'UTF8')),'hex'),q.baseline_bytes,q.limit_bytes,c.expires_at,c.status
 FROM remnawave_import_clients m JOIN vpn_clients c ON c.id=m.client_id
 JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
 WHERE m.import_id=NEW.import_id AND m.source_present AND m.deleted_at IS NULL AND c.tenant_id=NEW.tenant_id
 AND q.uplink_bytes=0 AND q.downlink_bytes=0;
 SELECT count(*) INTO actual FROM pauk_native_cutover.clients WHERE import_id=NEW.import_id;
 SELECT count(*) INTO expected FROM remnawave_import_clients WHERE import_id=NEW.import_id AND source_present AND deleted_at IS NULL AND client_id IS NOT NULL;
 IF actual=0 OR expected<>actual THEN RAISE EXCEPTION 'NATIVE_CAPTURE_CLIENT_BASELINE_NOT_EMPTY'; END IF;
 RETURN NEW;
END $$;


--
-- Name: capture(); Type: FUNCTION; Schema: pauk_native_cutover; Owner: -
--

CREATE FUNCTION pauk_native_cutover.capture() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE s pauk_native_cutover.sessions%ROWTYPE; up_delta bigint; down_delta bigint;
BEGIN
 SELECT h.* INTO s FROM pauk_native_cutover.sessions h JOIN pauk_native_cutover.clients c USING(import_id)
 WHERE c.client_id=NEW.client_id AND h.state<>'published' FOR SHARE OF h;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM pauk_native_cutover.nodes n JOIN pauk_native_cutover.sessions h USING(import_id) WHERE n.node_id=NEW.node_id AND h.state<>'published') THEN
   RAISE EXCEPTION 'NATIVE_CAPTURE_UNMAPPED_CLIENT';
  END IF;
  RETURN NEW;
 END IF;
 IF s.state='frozen' THEN RAISE EXCEPTION 'NATIVE_CAPTURE_FROZEN'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pauk_native_cutover.nodes WHERE import_id=s.import_id AND node_id=NEW.node_id) THEN
  RAISE EXCEPTION 'NATIVE_CAPTURE_UNTRACKED_NODE';
 END IF;
 IF NEW.sample_sequence<=0 OR NEW.counter_epoch !~ '^[0-9a-f]{32}$' OR NEW.counter_epoch=repeat('0',32)
  OR NEW.uplink_bytes<0 OR NEW.downlink_bytes<0 THEN RAISE EXCEPTION 'NATIVE_CAPTURE_UNORDERED_COUNTER'; END IF;
 up_delta:=NEW.uplink_bytes;down_delta:=NEW.downlink_bytes;
 IF TG_OP='UPDATE' THEN
  IF NEW.sample_sequence<=OLD.sample_sequence THEN
   IF NEW.sample_sequence=OLD.sample_sequence AND NEW.counter_epoch=OLD.counter_epoch
    AND NEW.uplink_bytes=OLD.uplink_bytes AND NEW.downlink_bytes=OLD.downlink_bytes THEN RETURN NEW; END IF;
   RAISE EXCEPTION 'NATIVE_CAPTURE_COUNTER_REGRESSION';
  END IF;
  IF NEW.counter_epoch=OLD.counter_epoch THEN
   up_delta:=NEW.uplink_bytes-OLD.uplink_bytes;down_delta:=NEW.downlink_bytes-OLD.downlink_bytes;
  END IF;
 END IF;
 IF up_delta<0 OR down_delta<0 THEN RAISE EXCEPTION 'NATIVE_CAPTURE_COUNTER_REGRESSION'; END IF;
 INSERT INTO pauk_native_cutover.events(import_id,node_id,client_id,sequence,epoch,observed_at,first_connected_at,last_online_at,uplink,downlink,uplink_delta,downlink_delta)
 VALUES(s.import_id,NEW.node_id,NEW.client_id,NEW.sample_sequence,NEW.counter_epoch,NEW.observed_at,NEW.first_connected_at,NEW.last_online_at,NEW.uplink_bytes,NEW.downlink_bytes,up_delta,down_delta);
 RETURN NEW;
END $_$;


--
-- Name: freeze_capture(uuid, text); Type: FUNCTION; Schema: pauk_native_cutover; Owner: -
--

CREATE FUNCTION pauk_native_cutover.freeze_capture(p_import uuid, p_fence text) RETURNS jsonb
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public', 'pauk_native_cutover'
    AS $_$
DECLARE tenant uuid;s pauk_native_cutover.sessions%ROWTYPE;result jsonb;events jsonb;
BEGIN
 IF p_import IS NULL OR p_fence IS NULL OR p_fence !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'NATIVE_CAPTURE_INVALID_FENCE'; END IF;
 SELECT tenant_id INTO tenant FROM pauk_native_cutover.sessions WHERE import_id=p_import;
 IF NOT FOUND THEN RAISE EXCEPTION 'NATIVE_CAPTURE_UNAVAILABLE'; END IF;
 -- Same lock/order as SaveTrafficDelivery and SaveHealth. No accepted report
 -- can race the snapshot; a later report is rejected with its whole TX intact.
 PERFORM pg_advisory_xact_lock(1448103504,hashtext(tenant::text));
 SELECT * INTO STRICT s FROM pauk_native_cutover.sessions WHERE import_id=p_import FOR UPDATE;
 IF s.state='frozen' THEN
  IF s.fence_sha256<>p_fence THEN RAISE EXCEPTION 'NATIVE_CAPTURE_FENCE_CHANGED'; END IF;
  RETURN s.snapshot;
 END IF;
 IF s.state<>'capturing' OR NOT EXISTS(SELECT 1 FROM remnawave_cutovers c JOIN remnawave_imports i ON i.id=c.import_id JOIN bot_profiles b ON b.tenant_id=c.tenant_id
  WHERE c.import_id=p_import AND c.state='rollback_required' AND i.state='rollback_required' AND b.state='paused') THEN
  RAISE EXCEPTION 'NATIVE_CAPTURE_ROLLBACK_PHASE_REQUIRED';
 END IF;
 IF EXISTS(
  SELECT 1 FROM pauk_native_cutover.clients m
  LEFT JOIN vpn_clients c ON c.id=m.client_id
  LEFT JOIN vpn_client_continuous_quotas q ON q.client_id=m.client_id
  LEFT JOIN LATERAL(SELECT coalesce(sum(uplink_delta),0) u,coalesce(sum(downlink_delta),0) d FROM pauk_native_cutover.events WHERE import_id=m.import_id AND client_id=m.client_id) e ON true
  WHERE m.import_id=p_import AND (c.tenant_id IS DISTINCT FROM tenant OR q.baseline_bytes IS DISTINCT FROM m.baseline_bytes
   OR q.limit_bytes IS DISTINCT FROM m.limit_bytes OR c.expires_at IS DISTINCT FROM m.expires_at OR c.status IS DISTINCT FROM m.status
   OR encode(sha256(convert_to(c.vless_uuid::text,'UTF8')),'hex') IS DISTINCT FROM m.credential_sha256
   OR q.uplink_bytes IS DISTINCT FROM e.u OR q.downlink_bytes IS DISTINCT FROM e.d)
 ) THEN RAISE EXCEPTION 'NATIVE_CAPTURE_ACCOUNTING_DRIFT'; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY node_id,client_id,sequence),'[]') INTO events FROM pauk_native_cutover.events e WHERE import_id=p_import;
 result:=jsonb_build_object('kind','native-return-capture-v1','import_id',p_import,'request_sha256',s.request_sha256,
  'inventory_sha256',s.inventory_sha256,'fence_sha256',p_fence,'physical_proof','owner_attestation',
  'events_sha256',encode(sha256(convert_to(events::text,'UTF8')),'hex'),
  'events',events,
  'clients',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY source_user_id),'[]') FROM pauk_native_cutover.clients c WHERE import_id=p_import),
  'nodes',(SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY source_node_id),'[]') FROM pauk_native_cutover.nodes n WHERE import_id=p_import),
  'delivery_checkpoints',(SELECT coalesce(jsonb_agg(jsonb_build_object('node_id',n.node_id,'sequence',coalesce(d.sample_sequence,0),'recorded_at',d.recorded_at) ORDER BY n.node_id),'[]') FROM pauk_native_cutover.nodes n LEFT JOIN node_traffic_delivery d ON d.node_id=n.node_id WHERE n.import_id=p_import));
 UPDATE pauk_native_cutover.sessions SET state='frozen',fence_sha256=p_fence,snapshot=result WHERE import_id=p_import;
 RETURN result;
END $_$;


--
-- Name: immutable(); Type: FUNCTION; Schema: pauk_native_cutover; Owner: -
--

CREATE FUNCTION pauk_native_cutover.immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
 BEGIN RAISE EXCEPTION 'NATIVE_CAPTURE_HISTORY_IMMUTABLE'; END $$;


--
-- Name: published(); Type: FUNCTION; Schema: pauk_native_cutover; Owner: -
--

CREATE FUNCTION pauk_native_cutover.published() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public', 'pauk_native_cutover'
    AS $$
BEGIN
 IF NEW.state='active' THEN
  UPDATE pauk_native_cutover.sessions SET state='published' WHERE import_id=NEW.import_id AND state='capturing';
  IF NOT FOUND THEN RAISE EXCEPTION 'NATIVE_CAPTURE_PUBLICATION_AFTER_FREEZE'; END IF;
 END IF;
 RETURN NEW;
END $$;


--
-- Name: agent_version_rank(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.agent_version_rank(v text) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    AS $_$
 SELECT CASE WHEN v ~ '^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$'
 THEN split_part(v,'.',1)::bigint*100000000 + split_part(v,'.',2)::bigint*10000 + split_part(v,'.',3)::bigint END
$_$;


--
-- Name: allocate_protocol_ingress_port(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.allocate_protocol_ingress_port() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 INSERT INTO protocol_ingress_ports(service_id) VALUES(NEW.id) ON CONFLICT DO NOTHING;
 RETURN NEW;
END $$;


--
-- Name: bot_client_deleted(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.bot_client_deleted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 UPDATE bot_subscription_aliases a SET state='revoked',revoked_at=COALESCE(revoked_at,now())
  FROM bot_accounts b WHERE b.client_id=OLD.id AND a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id;
 DELETE FROM bot_devices d USING bot_accounts b
  WHERE b.client_id=OLD.id AND d.tenant_id=b.tenant_id AND d.legacy_id=b.legacy_id;
 DELETE FROM bot_account_squads s USING bot_accounts b
  WHERE b.client_id=OLD.id AND s.tenant_id=b.tenant_id AND s.legacy_id=b.legacy_id;
 UPDATE bot_accounts SET deleted_client_id=OLD.id,client_id=NULL,deleted_at=now(),updated_at=now(),
  telegram_id=NULL,email=NULL,description=NULL WHERE client_id=OLD.id;
 RETURN OLD;
END;
$$;


--
-- Name: detach_removed_node_group_services(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.detach_removed_node_group_services() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NEW.status IN ('decommissioning','retired') AND OLD.status IS DISTINCT FROM NEW.status THEN
  WITH removed AS (
   DELETE FROM vpn_access_plan_services ps USING vpn_services s
   WHERE ps.service_id=s.id AND ps.tenant_id=s.tenant_id AND s.node_id=NEW.id
   RETURNING ps.tenant_id,ps.plan_id
  )
  INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,payload)
  SELECT tenant_id,NEW.id,'access_plan.node_services_removed','system',
   jsonb_build_object('plan_id',plan_id,'removed_service_count',count(*),'node_status',NEW.status)
  FROM removed GROUP BY tenant_id,plan_id;
 END IF;
 RETURN NEW;
END $$;


--
-- Name: enforce_amneziawg_settings_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_amneziawg_settings_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
  WHERE s.id=NEW.service_id AND s.tenant_id=NEW.tenant_id AND s.protocol='amneziawg' AND n.runtime_core='amneziawg') THEN
  RAISE EXCEPTION 'AmneziaWG settings require their own node runtime' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enforce_bot_profile_origin(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_bot_profile_origin() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (NEW.profile_kind,NEW.import_id) IS DISTINCT FROM (OLD.profile_kind,OLD.import_id) THEN
  RAISE EXCEPTION 'Bot profile origin is immutable';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enforce_desired_runtime_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_desired_runtime_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE selected TEXT; requested TEXT;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id;
 requested := NEW.document->'core'->>'type';
 -- Old recovery fixtures/records may omit the core. New Hysteria assignments
 -- require an explicit match, and no declared core may cross the node boundary.
 IF (requested IS NOT NULL OR selected='hysteria2') AND requested IS DISTINCT FROM selected THEN
  RAISE EXCEPTION 'desired runtime differs from node selection' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enforce_imported_reality_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_imported_reality_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE expected JSONB; public TEXT;
BEGIN
 SELECT b.service_spec->'reality', j.value->>'reality_public_key' INTO expected,public
 FROM node_xray_profile_bindings b JOIN node_xray_profiles p USING(node_id,tenant_id)
 CROSS JOIN LATERAL jsonb_array_elements(p.profile->'bindings') j
 WHERE b.service_id=NEW.service_id AND j.value->>'service_id'=b.service_id::text;
 IF FOUND THEN
  IF expected IS NULL OR (NEW.destination,NEW.server_name,NEW.short_id,NEW.secret_ref) IS DISTINCT FROM
     (expected->>'destination',expected->>'server_name',expected->>'short_id',expected->>'secret_ref')
     OR (NEW.public_key IS NOT NULL AND NEW.public_key IS DISTINCT FROM public) THEN
   RAISE EXCEPTION 'imported Reality identity differs from reviewed source' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.short_id !~ '^[0-9a-f]{16}$' THEN
  RAISE EXCEPTION 'ordinary Reality service requires a 16-hex Short ID' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$_$;


--
-- Name: enforce_imported_service_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_imported_service_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE profile_state TEXT; expected JSONB;
BEGIN
 SELECT state INTO profile_state FROM node_xray_profiles WHERE node_id=NEW.node_id;
 IF FOUND THEN
  SELECT service_spec INTO expected FROM node_xray_profile_bindings
   WHERE service_id=NEW.id AND node_id=NEW.node_id AND tenant_id=NEW.tenant_id;
  IF NOT FOUND OR (NEW.protocol,NEW.listen,NEW.port,NEW.transport,NEW.security) IS DISTINCT FROM
    (expected->>'protocol',expected->>'listen',(expected->>'port')::integer,expected->>'transport',expected->>'security')
    OR (NEW.enabled AND profile_state<>'active') THEN
   RAISE EXCEPTION 'imported service differs from reviewed binding or is not active' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enforce_imported_subscription_head(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_imported_subscription_head() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (NEW.tenant_id,NEW.import_id) IS DISTINCT FROM (OLD.tenant_id,OLD.import_id)
    OR (OLD.state<>'prepared' AND (NEW.state='prepared' OR NEW.revision_id<>OLD.revision_id)) THEN
  RAISE EXCEPTION 'active imported subscription identity cannot be rewritten' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enforce_protocol_template_binding(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_protocol_template_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM vpn_services s JOIN protocol_template_installations i
 ON i.service_id=s.id AND i.node_id=s.node_id AND i.tenant_id=s.tenant_id
 WHERE s.id=NEW.service_id AND s.tenant_id=NEW.tenant_id AND s.node_id=NEW.node_id
 AND i.request_key=NEW.request_key AND i.template_id=NEW.template_id AND i.template_version=NEW.template_version) THEN
  RAISE EXCEPTION 'template service binding differs from installation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;


--
-- Name: enforce_service_runtime_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_service_runtime_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE selected TEXT; imported BOOLEAN;
BEGIN
 SELECT runtime_core INTO STRICT selected FROM nodes WHERE id=NEW.node_id FOR UPDATE;
 imported := selected='xray' AND EXISTS(
  SELECT 1 FROM node_xray_profile_bindings b WHERE b.service_id=NEW.id AND b.node_id=NEW.node_id
   AND b.tenant_id=NEW.tenant_id AND b.service_spec->>'protocol'=NEW.protocol
   AND b.service_spec->>'transport'=NEW.transport AND b.service_spec->>'security'=NEW.security);
 IF ((selected='hysteria2') IS DISTINCT FROM (NEW.protocol='hysteria2') AND NOT imported)
    OR (selected='openvpn') IS DISTINCT FROM (NEW.protocol='openvpn')
    OR (selected='pptp') IS DISTINCT FROM (NEW.protocol='pptp')
    OR (selected='amneziawg') IS DISTINCT FROM (NEW.protocol='amneziawg')
    OR (selected='wireguard' AND NEW.protocol<>'wireguard') THEN
  RAISE EXCEPTION 'service runtime differs from node selection' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='hysteria2' AND (NEW.transport<>'udp' OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'Hysteria requires UDP and TLS' USING ERRCODE='23514';
 END IF;
 IF NEW.protocol='openvpn' AND (NEW.transport NOT IN ('udp','tcp') OR NEW.security<>'tls') THEN
  RAISE EXCEPTION 'OpenVPN requires TCP or UDP and TLS' USING ERRCODE='23514';
 END IF;
 IF selected='wireguard' THEN
  IF NEW.transport<>'udp' OR NEW.security<>'wireguard' OR NEW.listen NOT IN ('0.0.0.0','::') THEN
   RAISE EXCEPTION 'native WireGuard requires wildcard UDP' USING ERRCODE='23514';
  END IF;
  IF NEW.enabled AND EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.node_id AND id<>NEW.id AND enabled) THEN
   RAISE EXCEPTION 'native WireGuard allows one enabled service' USING ERRCODE='23514';
  END IF;
 END IF;
 IF selected='amneziawg' THEN
  IF NEW.transport<>'udp' OR NEW.security<>'amneziawg' OR NEW.listen NOT IN ('0.0.0.0','::') THEN
   RAISE EXCEPTION 'AmneziaWG requires wildcard UDP' USING ERRCODE='23514';
  END IF;
  IF NEW.enabled AND EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.node_id AND id<>NEW.id AND enabled) THEN
   RAISE EXCEPTION 'AmneziaWG allows one enabled service' USING ERRCODE='23514';
  END IF;
 END IF;
 IF selected='pptp' THEN
  IF NEW.transport<>'tcp,gre' OR NEW.security<>'mppe' OR NEW.port<>1723 OR (NEW.public_port IS NOT NULL AND NEW.public_port<>1723) THEN
   RAISE EXCEPTION 'PPTP requires TCP1723, GRE and MPPE' USING ERRCODE='23514';
  END IF;
  IF NEW.enabled AND EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.node_id AND id<>NEW.id AND enabled) THEN
   RAISE EXCEPTION 'PPTP allows one enabled service per node' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enforce_xray_activation_monotonic(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_xray_activation_monotonic() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF OLD.state='active' AND NEW.state<>'active' THEN
  RAISE EXCEPTION 'an adopted Xray profile cannot return to preparation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: enqueue_billing_webhook(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enqueue_billing_webhook() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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


--
-- Name: guard_imported_tls_certificate(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.guard_imported_tls_certificate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM imported_tls_certificates WHERE certificate_id=OLD.id) THEN
  IF (NEW.id,NEW.node_id,NEW.tenant_id,NEW.domain,NEW.certificate_ref) IS DISTINCT FROM
     (OLD.id,OLD.node_id,OLD.tenant_id,OLD.domain,OLD.certificate_ref) THEN
   RAISE EXCEPTION 'imported certificate identity is immutable' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM node_xray_profiles p JOIN imported_tls_certificates t
   ON p.node_id=t.node_id AND p.import_id=t.import_id AND p.source_node_id=t.source_node_id
   WHERE t.certificate_id=NEW.id AND p.state='active') THEN
   IF NEW.auto_renew OR (NEW.fingerprint_sha256,NEW.issuer,NEW.not_before,NEW.not_after) IS DISTINCT FROM
      (OLD.fingerprint_sha256,OLD.issuer,OLD.not_before,OLD.not_after) THEN
    RAISE EXCEPTION 'imported certificate renewal is held' USING ERRCODE='23514';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: guard_imported_tls_job(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.guard_imported_tls_job() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM imported_tls_certificates c WHERE c.certificate_id=NEW.certificate_id
  AND NOT EXISTS(SELECT 1 FROM node_xray_profiles p WHERE p.node_id=c.node_id AND p.import_id=c.import_id AND p.source_node_id=c.source_node_id AND p.state='active')) THEN
  RAISE EXCEPTION 'imported certificate renewal is held' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: immutable_xray_profile(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.immutable_xray_profile() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 RAISE EXCEPTION 'imported Xray profile identity is immutable' USING ERRCODE='55000';
END;
$$;


--
-- Name: pauk_remnawave_ignore_late_traffic(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pauk_remnawave_ignore_late_traffic() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
BEGIN
    IF (NEW.uplink_bytes>OLD.uplink_bytes OR NEW.downlink_bytes>OLD.downlink_bytes)
       AND current_setting('pauk.quota_client',true)=NEW.client_id::text
       AND nullif(current_setting('pauk.quota_observed_at',true),'')::timestamptz<OLD.baseline_at THEN
        UPDATE bot_accounts SET lifetime_offset_bytes=least(9000000000000000::bigint,
            lifetime_offset_bytes+NEW.uplink_bytes-OLD.uplink_bytes+NEW.downlink_bytes-OLD.downlink_bytes)
        WHERE client_id=NEW.client_id;
        NEW.uplink_bytes := OLD.uplink_bytes;
        NEW.downlink_bytes := OLD.downlink_bytes;
    END IF;
    RETURN NEW;
END $$;


--
-- Name: pauk_remnawave_next_reset(text, text, timestamp with time zone, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pauk_remnawave_next_reset(policy text, zone text, created_at timestamp with time zone, after_at timestamp with time zone) RETURNS timestamp with time zone
    LANGUAGE plpgsql STABLE
    SET search_path TO 'public', 'pg_catalog'
    AS $$
DECLARE
    local_after timestamp := after_at AT TIME ZONE zone;
    origin_day date := (created_at AT TIME ZONE 'UTC')::date;
    utc_month date := date_trunc('month', after_at AT TIME ZONE 'UTC')::date;
    first_due_day date := (origin_day+interval '1 month')::date;
    month_day date;
    anchor_day date;
    scheduled timestamp;
    candidate timestamptz;
BEGIN
    CASE policy
      WHEN 'DAY' THEN
        scheduled := date_trunc('day',local_after) + interval '5 minutes';
        IF scheduled AT TIME ZONE zone <= after_at THEN scheduled := scheduled+interval '1 day'; END IF;
      WHEN 'WEEK' THEN
        scheduled := date_trunc('week',local_after) + interval '15 minutes';
        IF scheduled AT TIME ZONE zone <= after_at THEN scheduled := scheduled+interval '7 days'; END IF;
      WHEN 'MONTH' THEN
        scheduled := date_trunc('month',local_after) + interval '20 minutes';
        IF scheduled AT TIME ZONE zone <= after_at THEN scheduled := scheduled+interval '1 month'; END IF;
      WHEN 'MONTH_ROLLING' THEN
        -- Remnawave selects the anniversary in its UTC database. Its scheduler
        -- checks for due clients each day at 00:10 in the scheduler's zone.
        utc_month := greatest(utc_month,date_trunc('month',first_due_day::timestamp)::date);
        FOR offset_month IN 0..2 LOOP
          month_day := (utc_month + make_interval(months=>offset_month))::date;
          anchor_day := month_day + (least(extract(day FROM origin_day)::integer,
              extract(day FROM month_day+interval '1 month - 1 day')::integer)-1);
          scheduled := date_trunc('day',(anchor_day::timestamp AT TIME ZONE 'UTC') AT TIME ZONE zone)+interval '10 minutes';
          candidate := scheduled AT TIME ZONE zone;
          IF (candidate AT TIME ZONE 'UTC')::date < anchor_day THEN
            candidate := (scheduled+interval '1 day') AT TIME ZONE zone;
          END IF;
          IF anchor_day >= first_due_day AND candidate > after_at AND
             (candidate AT TIME ZONE 'UTC')::date = anchor_day THEN
            RETURN candidate;
          END IF;
        END LOOP;
        RAISE EXCEPTION 'Unable to resolve rolling reset';
      ELSE RETURN NULL;
    END CASE;
    RETURN scheduled AT TIME ZONE zone;
END $$;


--
-- Name: pauk_remnawave_observe_traffic(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pauk_remnawave_observe_traffic() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
BEGIN
    IF EXISTS (SELECT FROM pauk_remnawave_quota_schedules WHERE client_id=NEW.client_id) THEN
        PERFORM pauk_remnawave_roll_quota(NEW.client_id,least(NEW.observed_at,clock_timestamp()));
        PERFORM set_config('pauk.quota_client',NEW.client_id::text,true);
        PERFORM set_config('pauk.quota_observed_at',NEW.observed_at::text,true);
    END IF;
    RETURN NEW;
END $$;


--
-- Name: pauk_remnawave_reset_due(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pauk_remnawave_reset_due() RETURNS integer
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
DECLARE
    boundary timestamptz := statement_timestamp();
    owner_id uuid;
    wanted uuid;
    reset_count integer := 0;
BEGIN
    FOR owner_id IN
        SELECT DISTINCT c.tenant_id
        FROM pauk_remnawave_quota_schedules s JOIN vpn_clients c ON c.id=s.client_id
        WHERE s.next_reset_at<=boundary ORDER BY c.tenant_id
    LOOP
      IF pg_try_advisory_xact_lock(1448103504,hashtext(owner_id::text)) THEN
        FOR wanted IN
            SELECT s.client_id FROM pauk_remnawave_quota_schedules s
            JOIN vpn_clients c ON c.id=s.client_id
            WHERE c.tenant_id=owner_id AND s.next_reset_at<=boundary
            ORDER BY s.next_reset_at,s.client_id LIMIT 5000
        LOOP
          IF pauk_remnawave_roll_quota(wanted,boundary) THEN reset_count := reset_count+1; END IF;
        END LOOP;
      END IF;
    END LOOP;
    RETURN reset_count;
END $$;


--
-- Name: pauk_remnawave_roll_quota(uuid, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.pauk_remnawave_roll_quota(wanted uuid, through_at timestamp with time zone) RETURNS boolean
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
DECLARE
    schedule pauk_remnawave_quota_schedules%ROWTYPE;
    previous_upload bigint;
    previous_download bigint;
    cutoff timestamptz;
    following timestamptz;
BEGIN
    SELECT * INTO schedule
    FROM pauk_remnawave_quota_schedules
    WHERE client_id=wanted AND next_reset_at<=through_at FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;

    cutoff := schedule.next_reset_at;
    IF cutoff < through_at - interval '40 days' THEN
        cutoff := pauk_remnawave_next_reset(schedule.policy,schedule.source_timezone,schedule.source_created_at,through_at-interval '40 days');
    END IF;
    following := pauk_remnawave_next_reset(schedule.policy,schedule.source_timezone,schedule.source_created_at,cutoff);
    WHILE following <= through_at LOOP
        cutoff := following;
        following := pauk_remnawave_next_reset(schedule.policy,schedule.source_timezone,schedule.source_created_at,cutoff);
    END LOOP;

    SELECT uplink_bytes,downlink_bytes INTO STRICT previous_upload,previous_download
    FROM vpn_client_continuous_quotas WHERE client_id=wanted FOR UPDATE;
    UPDATE bot_accounts
    SET lifetime_offset_bytes=least(9000000000000000::bigint,lifetime_offset_bytes+previous_upload+previous_download),
        updated_at=now()
    WHERE client_id=wanted;
    -- Keep cumulative node counters so the next report cannot recharge this window.
    UPDATE vpn_client_continuous_quotas
    SET baseline_bytes=0,baseline_at=cutoff,uplink_bytes=0,downlink_bytes=0,updated_at=now()
    WHERE client_id=wanted;
    UPDATE pauk_remnawave_quota_schedules
    SET last_reset_at=cutoff,next_reset_at=following
    WHERE client_id=wanted;
    RETURN true;
END $$;


--
-- Name: protect_agent_release_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protect_agent_release_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Permit only this exact repair of the installer digest, and keep every
    -- other part of a published release identity immutable.
    IF OLD.version='0.2.39'
       AND OLD.binary_sha256='17d2bb8686404413e41da0d5347f33d40fd8af75a49991a993091ca4cbc0a834'
       AND OLD.installer_sha256='a23842f04ba2058890f7ffea7a9a9490da1f6c032be40c4f6a8bbce5306cd758'
       AND NEW.version=OLD.version
       AND NEW.binary_sha256=OLD.binary_sha256
       AND NEW.installer_sha256='81fade30562dec32487c02b3bcb973681459e9d3414bed0a549e0bdf352d5238'
       AND NEW.created_at=OLD.created_at THEN
        RETURN NEW;
    END IF;
    IF NEW.version<>OLD.version OR NEW.binary_sha256<>OLD.binary_sha256
       OR NEW.installer_sha256<>OLD.installer_sha256 OR NEW.created_at<>OLD.created_at THEN
        RAISE EXCEPTION 'agent release identity is immutable';
    END IF;
    RETURN NEW;
END $$;


--
-- Name: protect_node_retirement(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protect_node_retirement() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 RAISE EXCEPTION 'node retirement is immutable' USING ERRCODE='23514';
END $$;


--
-- Name: protect_node_runtime_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protect_node_runtime_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NEW.runtime_core IS DISTINCT FROM OLD.runtime_core THEN
  RAISE EXCEPTION 'node runtime selection is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: protect_retired_node(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protect_retired_node() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF OLD.status='retired' THEN
  RAISE EXCEPTION 'retired node is read only' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.status='retired' THEN
  IF NEW.agent_token_hash IS NOT NULL OR NEW.bootstrap_token_hash IS NOT NULL
   OR NOT EXISTS(SELECT 1 FROM node_retirements WHERE node_id=NEW.id)
   OR EXISTS(SELECT 1 FROM vpn_services WHERE node_id=NEW.id AND enabled)
   OR EXISTS(SELECT 1 FROM node_certificates WHERE node_id=NEW.id AND auto_renew)
  THEN RAISE EXCEPTION 'retirement prerequisites not satisfied' USING ERRCODE='23514'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;


--
-- Name: protocol_template_service_ready(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.protocol_template_service_ready(wanted uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
 SELECT NOT EXISTS(SELECT 1 FROM vpn_service_protocol_templates WHERE service_id=wanted)
 OR EXISTS(
  SELECT 1 FROM vpn_service_protocol_templates t
  JOIN protocol_template_installations i ON i.request_key=t.request_key
  JOIN vpn_services s ON s.id=t.service_id AND s.node_id=t.node_id AND s.tenant_id=t.tenant_id
  JOIN nodes n ON n.id=t.node_id AND n.tenant_id=t.tenant_id
  JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.applied_generation
  JOIN deployments d ON d.node_id=n.id AND d.generation=n.applied_generation AND d.status='healthy'
  WHERE t.service_id=wanted AND n.applied_generation>=i.generation
  AND coalesce(agent_version_rank(n.agent_version)>=agent_version_rank('0.2.45'),false)
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(ds.document->'services')='array' THEN ds.document->'services' ELSE '[]'::jsonb END) a
   WHERE a->>'id'=s.id::text AND a->>'protocol_template'=t.template_id
   AND a->>'port'=s.port::text AND a->>'listen'=s.listen)
 )
$$;


--
-- Name: reject_removed_node_group_service(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_removed_node_group_service() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE node_status text;
BEGIN
 SELECT n.status INTO node_status FROM vpn_services s JOIN nodes n ON n.id=s.node_id
 WHERE s.id=NEW.service_id AND s.tenant_id=NEW.tenant_id FOR SHARE OF n;
 IF node_status IN ('decommissioning','retired') THEN
  RAISE EXCEPTION 'removed node service cannot belong to an access plan' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;


--
-- Name: reject_retired_node_work(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reject_retired_node_work() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE current_status text;
BEGIN
 SELECT status INTO current_status FROM nodes WHERE id=NEW.node_id FOR SHARE;
 IF current_status='retired' THEN
  RAISE EXCEPTION 'retired node cannot accept work' USING ERRCODE='23514';
 END IF;
 IF current_status='decommissioning' AND TG_TABLE_NAME IN (
   'desired_states','vpn_services','node_certificates','certificate_jobs',
   'agent_fleet_jobs','agent_updaters','node_core_update_policies',
   'execution_fence_requests','rollout_plans','recovery_attempts'
 ) THEN
  RAISE EXCEPTION 'decommissioning node cannot accept new work' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: remnawave_record_initial_revision(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.remnawave_record_initial_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 INSERT INTO remnawave_inventory_revisions(import_id,inventory_sha256,inventory,report,captured_at,created_at)
 VALUES(NEW.id,NEW.inventory_sha256,NEW.inventory,NEW.report,NEW.captured_at,NEW.created_at);
 INSERT INTO remnawave_import_heads VALUES(NEW.id,NEW.inventory_sha256);
 RETURN NEW;
END;
$$;


--
-- Name: remnawave_reject_inventory_update(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.remnawave_reject_inventory_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 RAISE EXCEPTION 'Remnawave inventory history is immutable' USING ERRCODE='55000';
END;
$$;


--
-- Name: resolve_registered_device_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.resolve_registered_device_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE owner_client UUID; owner_legacy BIGINT;
BEGIN
 IF NEW.legacy_id IS NOT NULL THEN
  SELECT client_id INTO owner_client FROM bot_accounts
   WHERE tenant_id=NEW.tenant_id AND legacy_id=NEW.legacy_id;
  IF NOT FOUND OR (NEW.client_id IS NOT NULL AND NEW.client_id IS DISTINCT FROM owner_client) THEN
   RAISE EXCEPTION 'device owner mismatch' USING ERRCODE='23514';
  END IF;
  NEW.client_id=owner_client;
 ELSIF NEW.client_id IS NOT NULL THEN
  SELECT legacy_id INTO owner_legacy FROM bot_accounts
   WHERE tenant_id=NEW.tenant_id AND client_id=NEW.client_id AND deleted_at IS NULL;
  IF FOUND THEN NEW.legacy_id=owner_legacy; END IF;
 END IF;
 RETURN NEW;
END;
$$;


--
-- Name: vpn_client_quota_exceeded(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_client_quota_exceeded(wanted uuid) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
 SELECT COALESCE(
   (SELECT q.limit_bytes>0 AND q.baseline_bytes+q.uplink_bytes+q.downlink_bytes>=q.limit_bytes
    FROM vpn_client_continuous_quotas q WHERE q.client_id=wanted),
   (SELECT l.monthly_bytes>0 AND COALESCE(u.uplink_bytes+u.downlink_bytes,0)>=l.monthly_bytes
    FROM vpn_client_limits l LEFT JOIN vpn_client_usage_monthly u
     ON u.client_id=l.client_id AND u.period_start=date_trunc('month',now() AT TIME ZONE 'UTC')::date
    WHERE l.client_id=wanted),false)
$$;


--
-- Name: vpn_node_cascade_client(uuid, uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_node_cascade_client(node uuid, client uuid, credential text) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$
 SELECT EXISTS(SELECT 1 FROM vpn_effective_client_cascades e WHERE e.entry_node_id=node AND e.client_id=client)
 OR EXISTS(SELECT 1 FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,
 jsonb_array_elements(COALESCE(ds.document->'xray_cascades'->'entries','[]'::jsonb)) e,
 jsonb_array_elements(COALESCE(e->'clients','[]'::jsonb)) u
 WHERE n.id=node AND (u->>'stats_key'=client::text OR u->>'id'=credential));
$$;


--
-- Name: vpn_platform_assign_deployment_execution_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_assign_deployment_execution_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.execution_id IS NULL THEN
        NEW.execution_id := gen_random_uuid();
    END IF;

    IF NEW.execution_epoch IS NULL THEN
        UPDATE nodes
        SET execution_epoch = execution_epoch + 1
        WHERE id = NEW.node_id
        RETURNING execution_epoch
        INTO NEW.execution_epoch;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'deployment node % does not exist',
                NEW.node_id
                USING ERRCODE = '23503';
        END IF;
    ELSE
        UPDATE nodes
        SET execution_epoch = GREATEST(
            execution_epoch,
            NEW.execution_epoch
        )
        WHERE id = NEW.node_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'deployment node % does not exist',
                NEW.node_id
                USING ERRCODE = '23503';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: vpn_platform_guard_deployment_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_guard_deployment_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT vpn_platform_status_transition_allowed(
        OLD.status,
        NEW.status
    ) THEN
        RAISE EXCEPTION
            'invalid deployment transition: % -> %',
            OLD.status,
            NEW.status
        USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;


--
-- Name: vpn_platform_guard_execution_fence_request_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_guard_execution_fence_request_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.node_id IS DISTINCT FROM NEW.node_id
       OR OLD.deployment_id IS DISTINCT FROM NEW.deployment_id
       OR OLD.generation IS DISTINCT FROM NEW.generation
       OR OLD.execution_id IS DISTINCT FROM NEW.execution_id
       OR OLD.execution_epoch IS DISTINCT FROM NEW.execution_epoch
       OR OLD.target_owner_instance_id IS DISTINCT FROM NEW.target_owner_instance_id
       OR OLD.reason IS DISTINCT FROM NEW.reason
       OR OLD.requested_at IS DISTINCT FROM NEW.requested_at
    THEN
        RAISE EXCEPTION
            'execution fence request identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: vpn_platform_guard_execution_fence_request_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_guard_execution_fence_request_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'requested'
       AND NEW.state IN (
            'acknowledged',
            'cancelled'
       )
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'invalid execution fence request transition: % -> %',
        OLD.state,
        NEW.state
        USING ERRCODE = '23514';
END;
$$;


--
-- Name: vpn_platform_guard_execution_identity(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_guard_execution_identity() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.execution_id IS DISTINCT FROM NEW.execution_id
       OR OLD.execution_epoch IS DISTINCT FROM NEW.execution_epoch
    THEN
        RAISE EXCEPTION
            'deployment execution identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: vpn_platform_guard_execution_lease_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_guard_execution_lease_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'unclaimed'
       AND NEW.state IN (
            'active',
            'fenced'
       )
    THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'active'
       AND NEW.state IN (
            'fenced',
            'completed'
       )
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'invalid execution lease transition: % -> %',
        OLD.state,
        NEW.state
        USING ERRCODE = '23514';
END;
$$;


--
-- Name: vpn_platform_guard_rollout_outcome_transition(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_guard_rollout_outcome_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT vpn_platform_status_transition_allowed(
        OLD.outcome_status,
        NEW.outcome_status
    ) THEN
        RAISE EXCEPTION
            'invalid rollout outcome transition: % -> %',
            OLD.outcome_status,
            NEW.outcome_status
        USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;


--
-- Name: vpn_platform_status_transition_allowed(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vpn_platform_status_transition_allowed(old_status text, new_status text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
BEGIN
    IF old_status IS NOT DISTINCT FROM new_status THEN
        RETURN TRUE;
    END IF;

    IF old_status IS NULL THEN
        RETURN new_status IN (
            'pending',
            'applying',
            'healthy',
            'failed',
            'rolled_back'
        );
    END IF;

    IF old_status = 'pending' THEN
        RETURN new_status IN (
            'applying',
            'healthy',
            'failed',
            'rolled_back'
        );
    END IF;

    IF old_status = 'applying' THEN
        RETURN new_status IN (
            'healthy',
            'failed',
            'rolled_back'
        );
    END IF;

    IF old_status IN (
        'healthy',
        'failed',
        'rolled_back'
    ) THEN
        RETURN FALSE;
    END IF;

    RETURN FALSE;
END
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: clients; Type: TABLE; Schema: pauk_native_cutover; Owner: -
--

CREATE TABLE pauk_native_cutover.clients (
    import_id uuid NOT NULL,
    client_id uuid NOT NULL,
    source_user_id bigint NOT NULL,
    credential_sha256 text NOT NULL,
    baseline_bytes bigint NOT NULL,
    limit_bytes bigint NOT NULL,
    expires_at timestamp with time zone,
    status text NOT NULL
);


--
-- Name: events; Type: TABLE; Schema: pauk_native_cutover; Owner: -
--

CREATE TABLE pauk_native_cutover.events (
    import_id uuid NOT NULL,
    node_id uuid NOT NULL,
    client_id uuid NOT NULL,
    sequence bigint NOT NULL,
    epoch text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    first_connected_at timestamp with time zone,
    last_online_at timestamp with time zone,
    uplink bigint NOT NULL,
    downlink bigint NOT NULL,
    uplink_delta bigint NOT NULL,
    downlink_delta bigint NOT NULL,
    CONSTRAINT events_downlink_check CHECK ((downlink >= 0)),
    CONSTRAINT events_downlink_delta_check CHECK ((downlink_delta >= 0)),
    CONSTRAINT events_epoch_check CHECK ((epoch ~ '^[0-9a-f]{32}$'::text)),
    CONSTRAINT events_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT events_uplink_check CHECK ((uplink >= 0)),
    CONSTRAINT events_uplink_delta_check CHECK ((uplink_delta >= 0))
);


--
-- Name: nodes; Type: TABLE; Schema: pauk_native_cutover; Owner: -
--

CREATE TABLE pauk_native_cutover.nodes (
    import_id uuid NOT NULL,
    node_id uuid NOT NULL,
    source_node_id uuid NOT NULL
);


--
-- Name: sessions; Type: TABLE; Schema: pauk_native_cutover; Owner: -
--

CREATE TABLE pauk_native_cutover.sessions (
    import_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    request_sha256 text NOT NULL,
    inventory_sha256 text NOT NULL,
    state text DEFAULT 'capturing'::text NOT NULL,
    started_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    fence_sha256 text,
    snapshot jsonb,
    CONSTRAINT sessions_check CHECK (((state = 'frozen'::text) = ((fence_sha256 IS NOT NULL) AND (snapshot IS NOT NULL)))),
    CONSTRAINT sessions_fence_sha256_check CHECK (((fence_sha256 IS NULL) OR (fence_sha256 ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT sessions_state_check CHECK ((state = ANY (ARRAY['capturing'::text, 'frozen'::text, 'published'::text])))
);


--
-- Name: admin_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    security_version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    mfa_enabled boolean DEFAULT false NOT NULL,
    CONSTRAINT admin_accounts_password_hash_check CHECK (((length(password_hash) >= 40) AND (length(password_hash) <= 256))),
    CONSTRAINT admin_accounts_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'monitor'::text]))),
    CONSTRAINT admin_accounts_security_version_check CHECK ((security_version > 0)),
    CONSTRAINT admin_accounts_username_check CHECK ((username ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'::text)),
    CONSTRAINT admin_mfa_password_marker CHECK ((mfa_enabled = ("left"(password_hash, 4) = 'mfa$'::text)))
);


--
-- Name: admin_mfa; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_mfa (
    account_id uuid NOT NULL,
    secret_ciphertext text,
    pending_ciphertext text,
    pending_expires_at timestamp with time zone,
    pending_security_version bigint,
    last_totp_step bigint DEFAULT '-1'::integer NOT NULL,
    recovery_hashes text[] DEFAULT '{}'::text[] NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT admin_mfa_check CHECK (((pending_ciphertext IS NULL) = (pending_expires_at IS NULL))),
    CONSTRAINT admin_mfa_check1 CHECK (((pending_ciphertext IS NULL) = (pending_security_version IS NULL))),
    CONSTRAINT admin_mfa_last_totp_step_check CHECK ((last_totp_step >= '-1'::integer)),
    CONSTRAINT admin_mfa_recovery_hashes_check CHECK ((cardinality(recovery_hashes) <= 10))
);


--
-- Name: admin_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    token_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT admin_sessions_check CHECK ((expires_at > created_at)),
    CONSTRAINT admin_sessions_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: agent_fleet_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_fleet_attempts (
    job_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    result jsonb NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_fleet_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_fleet_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    run_id uuid NOT NULL,
    node_id uuid NOT NULL,
    from_version text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    claim_id uuid,
    claimed_at timestamp with time zone,
    completed_at timestamp with time zone,
    message text DEFAULT ''::text NOT NULL,
    binary_sha256 text,
    CONSTRAINT agent_fleet_jobs_check CHECK (((claim_id IS NULL) = (claimed_at IS NULL))),
    CONSTRAINT agent_fleet_jobs_message_check CHECK ((length(message) <= 256)),
    CONSTRAINT agent_fleet_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'claimed'::text, 'succeeded'::text, 'failed'::text, 'already_current'::text, 'superseded'::text])))
);


--
-- Name: agent_fleet_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_fleet_policy (
    singleton boolean DEFAULT true NOT NULL,
    auto_spread boolean DEFAULT true NOT NULL,
    target_version text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_fleet_policy_singleton_check CHECK (singleton)
);


--
-- Name: agent_fleet_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_fleet_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_key uuid DEFAULT gen_random_uuid() NOT NULL,
    target_version text NOT NULL,
    origin_node_id uuid,
    priority_node_id uuid,
    origin text NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    message text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT agent_fleet_runs_origin_check CHECK ((origin = ANY (ARRAY['manual'::text, 'observed'::text]))),
    CONSTRAINT agent_fleet_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'paused'::text, 'completed'::text])))
);


--
-- Name: agent_releases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_releases (
    version text NOT NULL,
    binary_sha256 text NOT NULL,
    installer_sha256 text NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_releases_binary_sha256_check CHECK ((binary_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT agent_releases_installer_sha256_check CHECK ((installer_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT agent_releases_version_check CHECK ((public.agent_version_rank(version) IS NOT NULL))
);


--
-- Name: agent_updaters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_updaters (
    node_id uuid NOT NULL,
    version text NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid,
    node_id uuid,
    event_type text NOT NULL,
    actor_type text NOT NULL,
    actor_id text,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: billing_entitlements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_entitlements (
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: billing_invoices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_invoices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    offer_id uuid NOT NULL,
    client_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    offer_name text NOT NULL,
    amount_minor bigint NOT NULL,
    currency text NOT NULL,
    duration_days integer NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    idempotency_key text NOT NULL,
    payment_reference text,
    payment_source text,
    paid_at timestamp with time zone,
    entitlement_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_client_id uuid,
    live_client_id uuid GENERATED ALWAYS AS (
CASE
    WHEN (deleted_client_id IS NULL) THEN client_id
    ELSE NULL::uuid
END) STORED,
    CONSTRAINT billing_deleted_client_not_pending_chk CHECK (((deleted_client_id IS NULL) OR (status <> 'pending'::text))),
    CONSTRAINT billing_invoice_client_identity_chk CHECK (((deleted_client_id IS NULL) OR (deleted_client_id = client_id))),
    CONSTRAINT billing_invoices_amount_minor_check CHECK (((amount_minor >= 1) AND (amount_minor <= '1000000000000'::bigint))),
    CONSTRAINT billing_invoices_check CHECK (((status = 'paid'::text) = (paid_at IS NOT NULL))),
    CONSTRAINT billing_invoices_check1 CHECK (((status <> 'paid'::text) OR ((payment_reference IS NOT NULL) AND (payment_source IS NOT NULL) AND (entitlement_expires_at IS NOT NULL)))),
    CONSTRAINT billing_invoices_currency_check CHECK ((currency = ANY (ARRAY['RUB'::text, 'USD'::text, 'EUR'::text, 'PLN'::text, 'SEK'::text]))),
    CONSTRAINT billing_invoices_duration_days_check CHECK (((duration_days >= 1) AND (duration_days <= 3650))),
    CONSTRAINT billing_invoices_idempotency_key_check CHECK (((length(idempotency_key) >= 8) AND (length(idempotency_key) <= 128))),
    CONSTRAINT billing_invoices_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'paid'::text, 'void'::text])))
);


--
-- Name: billing_offers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_offers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    name text NOT NULL,
    amount_minor bigint NOT NULL,
    currency text NOT NULL,
    duration_days integer NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_offers_amount_minor_check CHECK (((amount_minor >= 1) AND (amount_minor <= '1000000000000'::bigint))),
    CONSTRAINT billing_offers_currency_check CHECK ((currency = ANY (ARRAY['RUB'::text, 'USD'::text, 'EUR'::text, 'PLN'::text, 'SEK'::text]))),
    CONSTRAINT billing_offers_duration_days_check CHECK (((duration_days >= 1) AND (duration_days <= 3650))),
    CONSTRAINT billing_offers_name_check CHECK (((length(btrim(name)) >= 1) AND (length(btrim(name)) <= 200)))
);


--
-- Name: billing_payment_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_payment_events (
    event_id text NOT NULL,
    invoice_id uuid NOT NULL,
    payload_hash text NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_payment_events_event_id_check CHECK (((length(event_id) >= 8) AND (length(event_id) <= 128))),
    CONSTRAINT billing_payment_events_payload_hash_check CHECK ((payload_hash ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: bot_account_squads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_account_squads (
    tenant_id uuid NOT NULL,
    legacy_id bigint NOT NULL,
    source_uuid uuid NOT NULL
);


--
-- Name: bot_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_accounts (
    tenant_id uuid NOT NULL,
    legacy_id bigint NOT NULL,
    client_id uuid,
    username text NOT NULL,
    telegram_id bigint,
    email text,
    description text,
    hwid_device_limit integer,
    lifetime_offset_bytes bigint NOT NULL,
    source_created_at timestamp with time zone NOT NULL,
    source_present boolean DEFAULT true NOT NULL,
    deleted_client_id uuid,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    native_adopted boolean DEFAULT false NOT NULL,
    CONSTRAINT bot_accounts_check CHECK ((((client_id IS NOT NULL) AND (deleted_at IS NULL) AND (deleted_client_id IS NULL)) OR ((client_id IS NULL) AND (deleted_at IS NOT NULL) AND (deleted_client_id IS NOT NULL)))),
    CONSTRAINT bot_accounts_description_check CHECK ((octet_length(description) <= 4096)),
    CONSTRAINT bot_accounts_email_check CHECK ((octet_length(email) <= 320)),
    CONSTRAINT bot_accounts_hwid_device_limit_check CHECK (((hwid_device_limit >= 0) AND (hwid_device_limit <= 1000))),
    CONSTRAINT bot_accounts_legacy_id_check CHECK (((legacy_id >= 1) AND (legacy_id <= '9007199254740991'::bigint))),
    CONSTRAINT bot_accounts_lifetime_offset_bytes_check CHECK (((lifetime_offset_bytes >= 0) AND (lifetime_offset_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT bot_accounts_telegram_id_check CHECK (((telegram_id >= 0) AND (telegram_id <= '9007199254740991'::bigint))),
    CONSTRAINT bot_accounts_username_check CHECK (((octet_length(username) >= 1) AND (octet_length(username) <= 256)))
);


--
-- Name: bot_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_devices (
    tenant_id uuid NOT NULL,
    legacy_id bigint,
    hwid text NOT NULL,
    platform text,
    os_version text,
    device_model text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid,
    CONSTRAINT bot_devices_check CHECK (((client_id IS NOT NULL) OR (legacy_id IS NOT NULL))),
    CONSTRAINT bot_devices_device_model_check CHECK ((octet_length(device_model) <= 2048)),
    CONSTRAINT bot_devices_hwid_check CHECK (((octet_length(hwid) >= 1) AND (octet_length(hwid) <= 512))),
    CONSTRAINT bot_devices_os_version_check CHECK ((octet_length(os_version) <= 2048)),
    CONSTRAINT bot_devices_platform_check CHECK ((octet_length(platform) <= 2048))
);


--
-- Name: bot_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_operations (
    tenant_id uuid NOT NULL,
    operation_key text NOT NULL,
    fingerprint text NOT NULL,
    status_code integer NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT bot_operations_fingerprint_check CHECK ((fingerprint ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT bot_operations_operation_key_check CHECK ((operation_key ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT bot_operations_response_check CHECK ((octet_length((response)::text) <= 262144)),
    CONSTRAINT bot_operations_status_code_check CHECK ((status_code = ANY (ARRAY[200, 201, 204])))
);


--
-- Name: bot_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_profiles (
    tenant_id uuid NOT NULL,
    import_id uuid,
    inventory_sha256 text,
    subscription_base text NOT NULL,
    state text DEFAULT 'held'::text NOT NULL,
    source_identity_reviewed boolean DEFAULT false NOT NULL,
    next_native_id bigint DEFAULT '4503599627370496'::bigint NOT NULL,
    prepared_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    profile_kind text DEFAULT 'imported'::text NOT NULL,
    CONSTRAINT bot_profile_origin CHECK ((((profile_kind = 'imported'::text) AND (import_id IS NOT NULL) AND (inventory_sha256 IS NOT NULL)) OR ((profile_kind = 'native'::text) AND (import_id IS NULL) AND (inventory_sha256 IS NULL)))),
    CONSTRAINT bot_profiles_check CHECK (((state <> 'active'::text) OR ((activated_at IS NOT NULL) AND source_identity_reviewed))),
    CONSTRAINT bot_profiles_next_native_id_check CHECK (((next_native_id >= '4503599627370496'::bigint) AND (next_native_id <= '9007199254740992'::bigint))),
    CONSTRAINT bot_profiles_profile_kind_check CHECK ((profile_kind = ANY (ARRAY['imported'::text, 'native'::text]))),
    CONSTRAINT bot_profiles_state_check CHECK ((state = ANY (ARRAY['held'::text, 'active'::text, 'paused'::text]))),
    CONSTRAINT bot_profiles_subscription_base_check CHECK (((length(subscription_base) >= 9) AND (length(subscription_base) <= 4096)))
);


--
-- Name: bot_squads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_squads (
    tenant_id uuid NOT NULL,
    source_uuid uuid NOT NULL,
    name text NOT NULL,
    plan_id uuid,
    source_present boolean DEFAULT true NOT NULL,
    CONSTRAINT bot_squads_name_check CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 256)))
);


--
-- Name: bot_subscription_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_subscription_aliases (
    alias text NOT NULL,
    tenant_id uuid NOT NULL,
    legacy_id bigint NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT bot_subscription_aliases_alias_check CHECK ((alias ~ '^[A-Za-z0-9_-]{16,128}$'::text)),
    CONSTRAINT bot_subscription_aliases_check CHECK ((((state = 'active'::text) AND (revoked_at IS NULL)) OR ((state = 'revoked'::text) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT bot_subscription_aliases_state_check CHECK ((state = ANY (ARRAY['active'::text, 'revoked'::text])))
);


--
-- Name: certificate_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    operation text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    owner_instance_id uuid,
    lease_token_hash text,
    lease_expires_at timestamp with time zone,
    attempt integer DEFAULT 0 NOT NULL,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    claimed_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT certificate_jobs_attempt_chk CHECK ((attempt >= 0)),
    CONSTRAINT certificate_jobs_operation_chk CHECK ((operation = ANY (ARRAY['issue'::text, 'renew'::text, 'delete'::text]))),
    CONSTRAINT certificate_jobs_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'claimed'::text, 'completed'::text, 'failed'::text])))
);


--
-- Name: core_releases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.core_releases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    core_type text NOT NULL,
    version text NOT NULL,
    os text NOT NULL,
    architecture text NOT NULL,
    download_url text NOT NULL,
    sha256 text NOT NULL,
    channel text DEFAULT 'testing'::text NOT NULL,
    upstream_prerelease boolean DEFAULT false NOT NULL,
    approved boolean DEFAULT false NOT NULL,
    approved_at timestamp with time zone,
    approved_by text,
    revoked boolean DEFAULT false NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT core_releases_channel_check CHECK ((channel = ANY (ARRAY['testing'::text, 'canary'::text, 'stable'::text]))),
    CONSTRAINT core_releases_sha256_check CHECK ((sha256 ~ '^[0-9a-fA-F]{64}$'::text))
);


--
-- Name: deployment_execution_leases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployment_execution_leases (
    deployment_id uuid NOT NULL,
    node_id uuid NOT NULL,
    generation bigint NOT NULL,
    execution_id uuid NOT NULL,
    execution_epoch bigint NOT NULL,
    state text DEFAULT 'unclaimed'::text NOT NULL,
    owner_instance_id uuid,
    lease_token_hash text,
    claimed_at timestamp with time zone,
    renewed_at timestamp with time zone,
    lease_expires_at timestamp with time zone,
    fenced_at timestamp with time zone,
    completed_at timestamp with time zone,
    fencing_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT deployment_execution_leases_active_chk CHECK (((state <> 'active'::text) OR ((owner_instance_id IS NOT NULL) AND (lease_token_hash IS NOT NULL) AND (claimed_at IS NOT NULL) AND (renewed_at IS NOT NULL) AND (lease_expires_at IS NOT NULL)))),
    CONSTRAINT deployment_execution_leases_active_time_chk CHECK (((state <> 'active'::text) OR ((claimed_at IS NOT NULL) AND (renewed_at IS NOT NULL) AND (lease_expires_at IS NOT NULL) AND (renewed_at >= claimed_at) AND (lease_expires_at > renewed_at)))),
    CONSTRAINT deployment_execution_leases_completed_chk CHECK (((state <> 'completed'::text) OR (completed_at IS NOT NULL))),
    CONSTRAINT deployment_execution_leases_epoch_chk CHECK ((execution_epoch >= 1)),
    CONSTRAINT deployment_execution_leases_fenced_chk CHECK (((state <> 'fenced'::text) OR ((fenced_at IS NOT NULL) AND (NULLIF(btrim(fencing_reason), ''::text) IS NOT NULL)))),
    CONSTRAINT deployment_execution_leases_state_chk CHECK ((state = ANY (ARRAY['unclaimed'::text, 'active'::text, 'fenced'::text, 'completed'::text]))),
    CONSTRAINT deployment_execution_leases_terminal_time_chk CHECK ((NOT ((completed_at IS NOT NULL) AND (fenced_at IS NOT NULL))))
);


--
-- Name: deployments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    node_id uuid NOT NULL,
    generation bigint NOT NULL,
    status text NOT NULL,
    previous_core_version text,
    requested_core_version text,
    applied_core_version text,
    error_message text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    core_release_id uuid,
    core_type text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    execution_id uuid DEFAULT gen_random_uuid() NOT NULL,
    execution_epoch bigint NOT NULL,
    CONSTRAINT deployments_execution_epoch_chk CHECK ((execution_epoch >= 1)),
    CONSTRAINT deployments_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'applying'::text, 'healthy'::text, 'failed'::text, 'rolled_back'::text])))
);


--
-- Name: desired_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.desired_states (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    node_id uuid NOT NULL,
    generation bigint NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: execution_fence_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.execution_fence_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    generation bigint NOT NULL,
    execution_id uuid NOT NULL,
    execution_epoch bigint NOT NULL,
    state text DEFAULT 'requested'::text NOT NULL,
    target_owner_instance_id uuid NOT NULL,
    reason text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by_instance_id uuid,
    cancelled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT execution_fence_requests_ack_chk CHECK (((state <> 'acknowledged'::text) OR ((acknowledged_at IS NOT NULL) AND (acknowledged_by_instance_id IS NOT NULL)))),
    CONSTRAINT execution_fence_requests_cancel_chk CHECK (((state <> 'cancelled'::text) OR (cancelled_at IS NOT NULL))),
    CONSTRAINT execution_fence_requests_epoch_chk CHECK ((execution_epoch >= 1)),
    CONSTRAINT execution_fence_requests_generation_chk CHECK ((generation >= 1)),
    CONSTRAINT execution_fence_requests_reason_chk CHECK ((NULLIF(btrim(reason), ''::text) IS NOT NULL)),
    CONSTRAINT execution_fence_requests_state_chk CHECK ((state = ANY (ARRAY['requested'::text, 'acknowledged'::text, 'cancelled'::text]))),
    CONSTRAINT execution_fence_requests_state_metadata_chk CHECK ((((state = 'requested'::text) AND (acknowledged_at IS NULL) AND (acknowledged_by_instance_id IS NULL) AND (cancelled_at IS NULL)) OR ((state = 'acknowledged'::text) AND (acknowledged_at IS NOT NULL) AND (acknowledged_by_instance_id IS NOT NULL) AND (cancelled_at IS NULL)) OR ((state = 'cancelled'::text) AND (acknowledged_at IS NULL) AND (acknowledged_by_instance_id IS NULL) AND (cancelled_at IS NOT NULL)))),
    CONSTRAINT execution_fence_requests_terminal_exclusive_chk CHECK ((NOT ((acknowledged_at IS NOT NULL) AND (cancelled_at IS NOT NULL))))
);


--
-- Name: imported_subscription_external_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.imported_subscription_external_accounts (
    revision_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    legacy_id bigint NOT NULL,
    source_external_id uuid CONSTRAINT imported_subscription_external_acco_source_external_id_not_null NOT NULL
);


--
-- Name: imported_subscription_host_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.imported_subscription_host_services (
    revision_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    source_host_id uuid NOT NULL,
    service_id uuid NOT NULL
);


--
-- Name: imported_subscription_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.imported_subscription_profiles (
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    state text DEFAULT 'prepared'::text NOT NULL,
    activation_sha256 text,
    prepared_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    CONSTRAINT imported_subscription_profiles_activation_sha256_check CHECK ((activation_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT imported_subscription_profiles_check CHECK (((state = 'prepared'::text) OR ((activation_sha256 IS NOT NULL) AND (activated_at IS NOT NULL)))),
    CONSTRAINT imported_subscription_profiles_check1 CHECK (((state <> 'prepared'::text) OR ((activation_sha256 IS NULL) AND (activated_at IS NULL)))),
    CONSTRAINT imported_subscription_profiles_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'active'::text, 'paused'::text])))
);


--
-- Name: imported_subscription_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.imported_subscription_revisions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    inventory_sha256 text NOT NULL,
    settings_sha256 text NOT NULL,
    bundle_sha256 text NOT NULL,
    bundle bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT imported_subscription_revisions_bundle_check CHECK (((octet_length(bundle) >= 1) AND (octet_length(bundle) <= 8388608))),
    CONSTRAINT imported_subscription_revisions_bundle_sha256_check CHECK ((bundle_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT imported_subscription_revisions_check CHECK ((encode(sha256(bundle), 'hex'::text) = bundle_sha256))
);


--
-- Name: imported_subscription_squad_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.imported_subscription_squad_services (
    revision_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    source_squad_id uuid NOT NULL,
    service_id uuid NOT NULL
);


--
-- Name: imported_tls_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.imported_tls_certificates (
    certificate_id uuid NOT NULL,
    node_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    inventory_sha256 text NOT NULL,
    source_node_id uuid NOT NULL,
    domain text NOT NULL,
    chain_sha256 text NOT NULL,
    fingerprint_sha256 text NOT NULL,
    adoption_sha256 text NOT NULL,
    prepared_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT imported_tls_certificates_adoption_sha256_check CHECK ((adoption_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT imported_tls_certificates_chain_sha256_check CHECK ((chain_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT imported_tls_certificates_fingerprint_sha256_check CHECK ((fingerprint_sha256 ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: ingress_companions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingress_companions (
    node_id uuid NOT NULL,
    version text NOT NULL,
    role text NOT NULL,
    addresses jsonb NOT NULL,
    seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ingress_companions_addresses_check CHECK ((jsonb_typeof(addresses) = 'array'::text)),
    CONSTRAINT ingress_companions_role_check CHECK ((role = ANY (ARRAY['entry'::text, 'origin'::text, 'bridge'::text])))
);


--
-- Name: ingress_provision_infrastructure; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingress_provision_infrastructure (
    singleton boolean DEFAULT true NOT NULL,
    config jsonb NOT NULL,
    CONSTRAINT ingress_provision_infrastructure_config_check CHECK ((jsonb_typeof(config) = 'object'::text)),
    CONSTRAINT ingress_provision_infrastructure_singleton_check CHECK (singleton)
);


--
-- Name: ingress_provision_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingress_provision_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_key uuid NOT NULL,
    node_id uuid NOT NULL,
    name text NOT NULL,
    address text NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    phase text DEFAULT 'preflight'::text NOT NULL,
    failure_code text DEFAULT ''::text NOT NULL,
    requested_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT ingress_provision_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'completed'::text, 'failed'::text])))
);


--
-- Name: ingress_provision_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingress_provision_tasks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    run_id uuid NOT NULL,
    node_id uuid NOT NULL,
    operation text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    owner_instance_id uuid,
    lease_until timestamp with time zone,
    failure_code text DEFAULT ''::text NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT ingress_provision_tasks_operation_check CHECK ((operation = ANY (ARRAY['inspect'::text, 'origin_sync'::text, 'bridge_sync'::text, 'prepare'::text, 'verify'::text, 'commit'::text, 'rollback'::text]))),
    CONSTRAINT ingress_provision_tasks_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'claimed'::text, 'completed'::text, 'failed'::text])))
);


--
-- Name: monitoring_incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.monitoring_incidents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule text NOT NULL,
    resource text NOT NULL,
    resource_name text NOT NULL,
    severity text NOT NULL,
    observed_since timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    opened_at timestamp with time zone,
    resolved_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    CONSTRAINT monitoring_incidents_check CHECK (((resolved_at IS NULL) OR (opened_at IS NOT NULL))),
    CONSTRAINT monitoring_incidents_severity_check CHECK ((severity = ANY (ARRAY['warning'::text, 'critical'::text])))
);


--
-- Name: monitoring_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.monitoring_runs (
    id boolean DEFAULT true NOT NULL,
    last_success_at timestamp with time zone NOT NULL,
    CONSTRAINT monitoring_runs_id_check CHECK (id)
);


--
-- Name: node_backup_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_backup_reports (
    node_id uuid NOT NULL,
    document jsonb NOT NULL,
    reported_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: node_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    domain text NOT NULL,
    provider text DEFAULT 'letsencrypt'::text NOT NULL,
    challenge_type text DEFAULT 'http-01'::text NOT NULL,
    environment text DEFAULT 'staging'::text NOT NULL,
    contact_email text,
    status text DEFAULT 'draft'::text NOT NULL,
    auto_renew boolean DEFAULT true NOT NULL,
    certificate_ref text NOT NULL,
    issuer text,
    fingerprint_sha256 text,
    not_before timestamp with time zone,
    not_after timestamp with time zone,
    observed_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_certificates_challenge_chk CHECK ((challenge_type = 'http-01'::text)),
    CONSTRAINT node_certificates_domain_chk CHECK ((btrim(domain) <> ''::text)),
    CONSTRAINT node_certificates_environment_chk CHECK ((environment = ANY (ARRAY['staging'::text, 'production'::text]))),
    CONSTRAINT node_certificates_provider_chk CHECK ((provider = 'letsencrypt'::text)),
    CONSTRAINT node_certificates_ref_chk CHECK ((certificate_ref ~ '^certificates/[0-9a-f-]{36}$'::text)),
    CONSTRAINT node_certificates_status_chk CHECK ((status = ANY (ARRAY['draft'::text, 'pending'::text, 'issuing'::text, 'active'::text, 'renewing'::text, 'failed'::text, 'revoked'::text, 'deleting'::text, 'deleted'::text])))
);


--
-- Name: node_client_traffic_cursors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_client_traffic_cursors (
    node_id uuid NOT NULL,
    client_id uuid NOT NULL,
    uplink_bytes bigint NOT NULL,
    downlink_bytes bigint NOT NULL,
    active_ips integer NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    counter_epoch text DEFAULT ''::text NOT NULL,
    sample_sequence bigint DEFAULT 0 NOT NULL,
    active_ips_known boolean DEFAULT true NOT NULL,
    first_connected_at timestamp with time zone,
    last_online_at timestamp with time zone,
    CONSTRAINT client_activity_timestamp_order CHECK (((first_connected_at IS NULL) OR (last_online_at IS NULL) OR (first_connected_at <= last_online_at))),
    CONSTRAINT node_client_traffic_cursors_active_ips_check CHECK (((active_ips >= 0) AND (active_ips <= 10000))),
    CONSTRAINT node_client_traffic_cursors_downlink_bytes_check CHECK (((downlink_bytes >= 0) AND (downlink_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT node_client_traffic_cursors_uplink_bytes_check CHECK (((uplink_bytes >= 0) AND (uplink_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT traffic_cursor_sample_metadata CHECK ((((counter_epoch = ''::text) AND (sample_sequence = 0)) OR ((counter_epoch ~ '^[0-9a-f]{32}$'::text) AND ((sample_sequence >= 1) AND (sample_sequence <= '9000000000000000'::bigint))))),
    CONSTRAINT traffic_unknown_address_count CHECK ((active_ips_known OR (active_ips = 0)))
);


--
-- Name: node_core_update_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_core_update_policies (
    node_id uuid NOT NULL,
    core_type text NOT NULL,
    policy text DEFAULT 'pinned'::text NOT NULL,
    pinned_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_core_update_policies_check CHECK ((((policy = 'pinned'::text) AND (pinned_version IS NOT NULL) AND (btrim(pinned_version) <> ''::text)) OR ((policy <> 'pinned'::text) AND (pinned_version IS NULL)))),
    CONSTRAINT node_core_update_policies_policy_check CHECK ((policy = ANY (ARRAY['pinned'::text, 'testing'::text, 'canary'::text, 'stable'::text])))
);


--
-- Name: node_health; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_health (
    node_id uuid NOT NULL,
    healthy boolean NOT NULL,
    applied_generation bigint DEFAULT 0 NOT NULL,
    core text,
    core_version text,
    message text,
    checked_at timestamp with time zone DEFAULT now() NOT NULL,
    last_known_good_core_version text,
    snapshot_count bigint DEFAULT 0 NOT NULL,
    latest_snapshot_id text,
    rollback_ready boolean DEFAULT false NOT NULL,
    CONSTRAINT node_health_snapshot_count_chk CHECK ((snapshot_count >= 0))
);


--
-- Name: node_ingress_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_ingress_policies (
    node_id uuid NOT NULL,
    mode text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_ingress_policies_mode_check CHECK ((mode = ANY (ARRAY['legacy'::text, 'direct'::text, 'enabled'::text]))),
    CONSTRAINT node_ingress_policies_revision_check CHECK ((revision > 0))
);


--
-- Name: node_metric_samples; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_metric_samples (
    node_id uuid NOT NULL,
    sample_bucket bigint NOT NULL,
    sampled_at timestamp with time zone DEFAULT now() NOT NULL,
    cpu_percent double precision NOT NULL,
    load_1 double precision NOT NULL,
    memory_total_bytes bigint NOT NULL,
    memory_used_bytes bigint NOT NULL,
    disk_total_bytes bigint NOT NULL,
    disk_used_bytes bigint NOT NULL,
    network_rx_bytes bigint NOT NULL,
    network_tx_bytes bigint NOT NULL,
    uptime_seconds bigint NOT NULL,
    cpu_steal_percent double precision,
    tcp_retrans_percent double precision,
    udp_receive_drops_per_second double precision,
    CONSTRAINT node_metric_samples_check CHECK (((memory_used_bytes >= 0) AND (memory_used_bytes <= memory_total_bytes))),
    CONSTRAINT node_metric_samples_check1 CHECK (((disk_used_bytes >= 0) AND (disk_used_bytes <= disk_total_bytes))),
    CONSTRAINT node_metric_samples_cpu_percent_check CHECK (((cpu_percent >= (0)::double precision) AND (cpu_percent <= (100)::double precision))),
    CONSTRAINT node_metric_samples_cpu_steal_percent_check CHECK (((cpu_steal_percent >= (0)::double precision) AND (cpu_steal_percent <= (100)::double precision))),
    CONSTRAINT node_metric_samples_disk_total_bytes_check CHECK ((disk_total_bytes >= 0)),
    CONSTRAINT node_metric_samples_load_1_check CHECK ((load_1 >= (0)::double precision)),
    CONSTRAINT node_metric_samples_memory_total_bytes_check CHECK ((memory_total_bytes >= 0)),
    CONSTRAINT node_metric_samples_network_rx_bytes_check CHECK ((network_rx_bytes >= 0)),
    CONSTRAINT node_metric_samples_network_tx_bytes_check CHECK ((network_tx_bytes >= 0)),
    CONSTRAINT node_metric_samples_tcp_retrans_percent_check CHECK (((tcp_retrans_percent >= (0)::double precision) AND (tcp_retrans_percent <= (100)::double precision))),
    CONSTRAINT node_metric_samples_udp_receive_drops_per_second_check CHECK (((udp_receive_drops_per_second >= (0)::double precision) AND (udp_receive_drops_per_second <= (1000000000)::double precision))),
    CONSTRAINT node_metric_samples_uptime_seconds_check CHECK ((uptime_seconds >= 0))
);


--
-- Name: node_reboot_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_reboot_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    requested_by text DEFAULT ''::text NOT NULL,
    owner_instance_id uuid,
    failure_code text,
    requested_last_seen_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    claimed_at timestamp with time zone,
    scheduled_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT node_reboot_jobs_failure_code_chk CHECK (((failure_code IS NULL) OR (failure_code = ANY (ARRAY['scheduler_unavailable'::text, 'request_expired'::text, 'node_not_ready'::text, 'operation_in_progress'::text])))),
    CONSTRAINT node_reboot_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'claimed'::text, 'scheduled'::text, 'failed'::text])))
);


--
-- Name: node_retirements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_retirements (
    node_id uuid NOT NULL,
    confirmed_name text NOT NULL,
    server_stopped boolean NOT NULL,
    retired_at timestamp with time zone DEFAULT now() NOT NULL,
    decommission_generation bigint,
    CONSTRAINT node_retirements_safe_shutdown_check CHECK ((server_stopped OR (decommission_generation IS NOT NULL)))
);


--
-- Name: node_security_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_security_policies (
    node_id uuid NOT NULL,
    mode text DEFAULT 'audit'::text NOT NULL,
    update_hold boolean DEFAULT false NOT NULL,
    revision bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_security_policies_mode_check CHECK ((mode = ANY (ARRAY['audit'::text, 'protect'::text]))),
    CONSTRAINT node_security_policies_revision_check CHECK ((revision > 0))
);


--
-- Name: node_security_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_security_reports (
    node_id uuid NOT NULL,
    report jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_security_reports_report_check CHECK ((jsonb_typeof(report) = 'object'::text))
);


--
-- Name: node_traffic_delivery; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_traffic_delivery (
    node_id uuid NOT NULL,
    sample_sequence bigint NOT NULL,
    recorded_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_traffic_delivery_sample_sequence_check CHECK ((sample_sequence > 0))
);


--
-- Name: node_xray_profile_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_xray_profile_bindings (
    node_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    service_id uuid NOT NULL,
    source_inbound_id uuid NOT NULL,
    source_enabled boolean NOT NULL,
    inbound_tag text NOT NULL,
    service_spec jsonb NOT NULL,
    CONSTRAINT node_xray_profile_bindings_check CHECK (((service_spec ->> 'id'::text) = (service_id)::text)),
    CONSTRAINT node_xray_profile_bindings_inbound_tag_check CHECK (((length(inbound_tag) >= 1) AND (length(inbound_tag) <= 256))),
    CONSTRAINT node_xray_profile_bindings_service_spec_check CHECK (((jsonb_typeof(service_spec) = 'object'::text) AND (octet_length((service_spec)::text) <= 16384))),
    CONSTRAINT node_xray_profile_bindings_service_spec_check1 CHECK (((NOT (service_spec ? 'clients'::text)) OR ((service_spec -> 'clients'::text) = '[]'::jsonb))),
    CONSTRAINT node_xray_profile_bindings_service_spec_check2 CHECK ((NOT (COALESCE((service_spec -> 'reality'::text), '{}'::jsonb) ? 'private_key'::text))),
    CONSTRAINT node_xray_profile_bindings_service_spec_check3 CHECK ((NOT (COALESCE((service_spec -> 'tls'::text), '{}'::jsonb) ?| ARRAY['certificate_file'::text, 'key_file'::text])))
);


--
-- Name: node_xray_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_xray_profiles (
    node_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    inventory_sha256 text NOT NULL,
    source_node_id uuid NOT NULL,
    source_profile_id uuid NOT NULL,
    profile_sha256 text NOT NULL,
    profile jsonb NOT NULL,
    state text DEFAULT 'prepared'::text NOT NULL,
    adoption_sha256 text,
    prepared_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    CONSTRAINT node_xray_profiles_adoption_sha256_check CHECK ((adoption_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT node_xray_profiles_check CHECK (((profile ->> 'sha256'::text) = profile_sha256)),
    CONSTRAINT node_xray_profiles_check1 CHECK (((state <> 'active'::text) OR ((adoption_sha256 IS NOT NULL) AND (activated_at IS NOT NULL)))),
    CONSTRAINT node_xray_profiles_profile_check CHECK (((jsonb_typeof(profile) = 'object'::text) AND (octet_length((profile)::text) <= 2097152))),
    CONSTRAINT node_xray_profiles_profile_sha256_check CHECK ((profile_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT node_xray_profiles_state_check CHECK ((state = ANY (ARRAY['prepared'::text, 'active'::text])))
);


--
-- Name: nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nodes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    bootstrap_token_hash text,
    bootstrap_used_at timestamp with time zone,
    agent_token_hash text,
    agent_version text,
    os_name text,
    os_version text,
    architecture text,
    desired_generation bigint DEFAULT 0 NOT NULL,
    applied_generation bigint DEFAULT 0 NOT NULL,
    last_seen_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    execution_epoch bigint DEFAULT 0 NOT NULL,
    runtime_core text DEFAULT 'xray'::text NOT NULL,
    CONSTRAINT nodes_execution_epoch_chk CHECK ((execution_epoch >= 0)),
    CONSTRAINT nodes_runtime_core_check CHECK ((runtime_core = ANY (ARRAY['xray'::text, 'hysteria2'::text, 'openvpn'::text, 'wireguard'::text, 'amneziawg'::text, 'pptp'::text])))
);


--
-- Name: pauk_remnawave_quota_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pauk_remnawave_quota_schedules (
    client_id uuid NOT NULL,
    policy text NOT NULL,
    source_timezone text NOT NULL,
    source_created_at timestamp with time zone NOT NULL,
    last_reset_at timestamp with time zone,
    next_reset_at timestamp with time zone NOT NULL,
    CONSTRAINT pauk_remnawave_quota_schedules_policy_check CHECK ((policy = ANY (ARRAY['DAY'::text, 'WEEK'::text, 'MONTH'::text, 'MONTH_ROLLING'::text])))
);


--
-- Name: platform_ingress_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_ingress_config (
    singleton boolean DEFAULT true NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    config jsonb NOT NULL,
    source_rules jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_ingress_config_config_check CHECK ((jsonb_typeof(config) = 'object'::text)),
    CONSTRAINT platform_ingress_config_revision_check CHECK ((revision > 0)),
    CONSTRAINT platform_ingress_config_singleton_check CHECK (singleton),
    CONSTRAINT platform_ingress_config_source_rules_check CHECK ((jsonb_typeof(source_rules) = 'array'::text))
);


--
-- Name: protocol_ingress_entry_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protocol_ingress_entry_nodes (
    entry_id text NOT NULL,
    node_id uuid NOT NULL,
    address inet NOT NULL,
    CONSTRAINT protocol_ingress_entry_nodes_address_check CHECK ((family(address) = 4))
);


--
-- Name: protocol_ingress_port_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.protocol_ingress_port_seq
    START WITH 30000
    INCREMENT BY 1
    MINVALUE 30000
    MAXVALUE 60999
    CACHE 1;


--
-- Name: protocol_ingress_ports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protocol_ingress_ports (
    service_id uuid NOT NULL,
    port integer DEFAULT nextval('public.protocol_ingress_port_seq'::regclass) NOT NULL,
    CONSTRAINT protocol_ingress_ports_port_check CHECK (((port >= 30000) AND (port <= 60999)))
);


--
-- Name: protocol_ingress_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protocol_ingress_reports (
    entry_id text NOT NULL,
    service_id uuid NOT NULL,
    fingerprint text NOT NULL,
    ready boolean NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT protocol_ingress_reports_fingerprint_check CHECK ((fingerprint ~ '^[a-f0-9]{64}$'::text))
);


--
-- Name: protocol_template_installations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protocol_template_installations (
    request_key uuid NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    service_id uuid NOT NULL,
    template_id text NOT NULL,
    template_version text NOT NULL,
    request_sha256 text NOT NULL,
    generation bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT protocol_template_installations_generation_check CHECK ((generation > 0)),
    CONSTRAINT protocol_template_installations_request_sha256_check CHECK ((request_sha256 ~ '^[a-f0-9]{64}$'::text))
);


--
-- Name: recovery_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recovery_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    source_deployment_id uuid NOT NULL,
    source_generation bigint NOT NULL,
    source_deployment_status text NOT NULL,
    base_desired_generation bigint NOT NULL,
    base_applied_generation bigint NOT NULL,
    proposed_generation bigint NOT NULL,
    core_type text NOT NULL,
    target_core_release_id uuid,
    target_version text,
    target_channel text,
    status text NOT NULL,
    blockers jsonb DEFAULT '[]'::jsonb NOT NULL,
    desired_state_preview jsonb,
    created_by text DEFAULT 'control-plane'::text NOT NULL,
    approved_by text,
    approved_at timestamp with time zone,
    executed_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    failure_reason text,
    deployment_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '01:00:00'::interval) NOT NULL,
    CONSTRAINT recovery_attempts_active_preview_chk CHECK (((status <> ALL (ARRAY['planned'::text, 'approved'::text, 'executed'::text])) OR (desired_state_preview IS NOT NULL))),
    CONSTRAINT recovery_attempts_active_release_chk CHECK (((status <> ALL (ARRAY['planned'::text, 'approved'::text, 'executed'::text])) OR (target_core_release_id IS NOT NULL))),
    CONSTRAINT recovery_attempts_active_source_generation_chk CHECK (((status <> ALL (ARRAY['planned'::text, 'approved'::text, 'executed'::text])) OR (source_generation = base_desired_generation))),
    CONSTRAINT recovery_attempts_active_source_status_chk CHECK (((status <> ALL (ARRAY['planned'::text, 'approved'::text, 'executed'::text])) OR (source_deployment_status = ANY (ARRAY['rolled_back'::text, 'pending'::text, 'applying'::text])))),
    CONSTRAINT recovery_attempts_blockers_chk CHECK ((jsonb_typeof(blockers) = 'array'::text)),
    CONSTRAINT recovery_attempts_executed_receipt_chk CHECK (((status <> 'executed'::text) OR (deployment_id IS NOT NULL))),
    CONSTRAINT recovery_attempts_expires_chk CHECK ((expires_at > created_at)),
    CONSTRAINT recovery_attempts_generation_sequence_chk CHECK ((proposed_generation = (base_desired_generation + 1))),
    CONSTRAINT recovery_attempts_source_status_chk CHECK ((source_deployment_status = ANY (ARRAY['pending'::text, 'applying'::text, 'healthy'::text, 'failed'::text, 'rolled_back'::text]))),
    CONSTRAINT recovery_attempts_status_chk CHECK ((status = ANY (ARRAY['blocked'::text, 'planned'::text, 'approved'::text, 'executed'::text, 'cancelled'::text, 'failed'::text, 'stale'::text])))
);


--
-- Name: remnawave_cutovers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remnawave_cutovers (
    import_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    request_sha256 text NOT NULL,
    inventory_sha256 text NOT NULL,
    subscription_revision_id uuid NOT NULL,
    request jsonb NOT NULL,
    result jsonb NOT NULL,
    state text DEFAULT 'verifying'::text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    publication_sha256 text,
    CONSTRAINT remnawave_cutovers_check CHECK (((state <> 'active'::text) OR ((verified_at IS NOT NULL) AND (publication_sha256 IS NOT NULL)))),
    CONSTRAINT remnawave_cutovers_publication_sha256_check CHECK ((publication_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT remnawave_cutovers_request_check CHECK (((jsonb_typeof(request) = 'object'::text) AND (octet_length((request)::text) <= 131072))),
    CONSTRAINT remnawave_cutovers_request_sha256_check CHECK ((request_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT remnawave_cutovers_result_check CHECK (((jsonb_typeof(result) = 'object'::text) AND (octet_length((result)::text) <= 131072))),
    CONSTRAINT remnawave_cutovers_state_check CHECK ((state = ANY (ARRAY['verifying'::text, 'active'::text, 'rollback_required'::text])))
);


--
-- Name: remnawave_import_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remnawave_import_clients (
    import_id uuid NOT NULL,
    source_user_id bigint NOT NULL,
    source_status text NOT NULL,
    client_id uuid,
    deleted_client_id uuid,
    deleted_client_name text,
    deleted_at timestamp with time zone,
    source_present boolean DEFAULT true NOT NULL,
    CONSTRAINT remnawave_client_identity_chk CHECK ((((client_id IS NOT NULL) AND (deleted_client_id IS NULL) AND (deleted_client_name IS NULL) AND (deleted_at IS NULL)) OR ((client_id IS NULL) AND (deleted_client_id IS NOT NULL) AND (deleted_client_name IS NOT NULL) AND (deleted_at IS NOT NULL)))),
    CONSTRAINT remnawave_import_clients_source_status_check CHECK ((source_status = ANY (ARRAY['ACTIVE'::text, 'DISABLED'::text, 'EXPIRED'::text, 'LIMITED'::text]))),
    CONSTRAINT remnawave_import_clients_source_user_id_check CHECK ((source_user_id > 0))
);


--
-- Name: remnawave_import_heads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remnawave_import_heads (
    import_id uuid NOT NULL,
    inventory_sha256 text NOT NULL
);


--
-- Name: remnawave_imports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remnawave_imports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    source_origin text NOT NULL,
    inventory_sha256 text NOT NULL,
    inventory bytea NOT NULL,
    report jsonb NOT NULL,
    user_count integer NOT NULL,
    state text DEFAULT 'held'::text NOT NULL,
    captured_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT remnawave_imports_inventory_check CHECK ((octet_length(inventory) <= 67108864)),
    CONSTRAINT remnawave_imports_inventory_sha256_check CHECK ((inventory_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT remnawave_imports_state_check CHECK ((state = ANY (ARRAY['held'::text, 'activating'::text, 'active'::text, 'rollback_required'::text]))),
    CONSTRAINT remnawave_imports_user_count_check CHECK (((user_count >= 0) AND (user_count <= 100000)))
);


--
-- Name: remnawave_inventory_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remnawave_inventory_revisions (
    import_id uuid NOT NULL,
    inventory_sha256 text NOT NULL,
    parent_sha256 text,
    sequence_id bigint NOT NULL,
    inventory bytea NOT NULL,
    report jsonb NOT NULL,
    captured_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT remnawave_inventory_revisions_inventory_check CHECK ((octet_length(inventory) <= 67108864)),
    CONSTRAINT remnawave_inventory_revisions_inventory_sha256_check CHECK ((inventory_sha256 ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: remnawave_inventory_revisions_sequence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.remnawave_inventory_revisions_sequence_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: remnawave_inventory_revisions_sequence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.remnawave_inventory_revisions_sequence_id_seq OWNED BY public.remnawave_inventory_revisions.sequence_id;


--
-- Name: remnawave_subscription_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.remnawave_subscription_settings (
    import_id uuid NOT NULL,
    settings_sha256 text NOT NULL,
    source bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT remnawave_subscription_settings_check CHECK ((encode(sha256(source), 'hex'::text) = settings_sha256)),
    CONSTRAINT remnawave_subscription_settings_settings_sha256_check CHECK ((settings_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT remnawave_subscription_settings_source_check CHECK (((octet_length(source) >= 1) AND (octet_length(source) <= 16777216)))
);


--
-- Name: reseller_children; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reseller_children (
    child_tenant_id uuid NOT NULL,
    parent_tenant_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT reseller_children_check CHECK ((child_tenant_id <> parent_tenant_id))
);


--
-- Name: rollout_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rollout_plans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    core_type text NOT NULL,
    policy text NOT NULL,
    pinned_version text,
    base_generation bigint NOT NULL,
    proposed_generation bigint NOT NULL,
    from_version text,
    target_core_release_id uuid,
    target_version text,
    target_channel text,
    status text NOT NULL,
    blockers jsonb DEFAULT '[]'::jsonb NOT NULL,
    desired_state_preview jsonb,
    created_by text DEFAULT 'control-plane'::text NOT NULL,
    approved_by text,
    approved_at timestamp with time zone,
    executed_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    failure_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '01:00:00'::interval) NOT NULL,
    deployment_id uuid,
    outcome_status text,
    outcome_at timestamp with time zone,
    outcome_reason text,
    request_key uuid,
    CONSTRAINT rollout_plans_blockers_check CHECK ((jsonb_typeof(blockers) = 'array'::text)),
    CONSTRAINT rollout_plans_check CHECK ((proposed_generation > base_generation)),
    CONSTRAINT rollout_plans_executed_requires_deployment_chk CHECK (((status <> 'executed'::text) OR (deployment_id IS NOT NULL))),
    CONSTRAINT rollout_plans_executed_requires_outcome_chk CHECK (((status <> 'executed'::text) OR (outcome_status IS NOT NULL))),
    CONSTRAINT rollout_plans_expires_after_created_chk CHECK ((expires_at > created_at)),
    CONSTRAINT rollout_plans_outcome_requires_executed_chk CHECK (((outcome_status IS NULL) OR (status = 'executed'::text))),
    CONSTRAINT rollout_plans_outcome_status_chk CHECK (((outcome_status IS NULL) OR (outcome_status = ANY (ARRAY['pending'::text, 'applying'::text, 'healthy'::text, 'failed'::text, 'rolled_back'::text])))),
    CONSTRAINT rollout_plans_policy_check CHECK ((policy = ANY (ARRAY['pinned'::text, 'testing'::text, 'canary'::text, 'stable'::text]))),
    CONSTRAINT rollout_plans_status_check CHECK ((status = ANY (ARRAY['blocked'::text, 'planned'::text, 'approved'::text, 'executed'::text, 'cancelled'::text, 'failed'::text, 'stale'::text])))
);


--
-- Name: service_ingress_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_ingress_policies (
    service_id uuid NOT NULL,
    mode text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT service_ingress_policies_mode_check CHECK ((mode = ANY (ARRAY['inherit'::text, 'direct'::text, 'enabled'::text]))),
    CONSTRAINT service_ingress_policies_revision_check CHECK ((revision > 0))
);


--
-- Name: tenant_api_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_api_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    role text NOT NULL,
    token_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    issued_by_token_id uuid,
    CONSTRAINT tenant_api_tokens_check CHECK ((expires_at > created_at)),
    CONSTRAINT tenant_api_tokens_name_check CHECK (((length(name) >= 1) AND (length(name) <= 100))),
    CONSTRAINT tenant_api_tokens_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'operator'::text, 'reseller'::text]))),
    CONSTRAINT tenant_api_tokens_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);


--
-- Name: tenant_auto_profile_publications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_auto_profile_publications (
    tenant_id uuid NOT NULL,
    generation bigint NOT NULL,
    service_ids uuid[] NOT NULL,
    fingerprint text NOT NULL,
    refreshed_at timestamp with time zone NOT NULL,
    available_nodes integer NOT NULL,
    available_services integer NOT NULL,
    CONSTRAINT tenant_auto_profile_publications_available_nodes_check CHECK ((available_nodes > 0)),
    CONSTRAINT tenant_auto_profile_publications_available_services_check CHECK ((available_services > 0)),
    CONSTRAINT tenant_auto_profile_publications_fingerprint_check CHECK ((fingerprint ~ '^[a-f0-9]{64}$'::text)),
    CONSTRAINT tenant_auto_profile_publications_generation_check CHECK ((generation > 0)),
    CONSTRAINT tenant_auto_profile_publications_service_ids_check CHECK (((cardinality(service_ids) >= 1) AND (cardinality(service_ids) <= 5000)))
);


--
-- Name: tenant_auto_profile_refresh_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_auto_profile_refresh_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    request_key uuid NOT NULL,
    origin text NOT NULL,
    status text NOT NULL,
    generation bigint NOT NULL,
    available_nodes integer NOT NULL,
    available_services integer NOT NULL,
    checked_at timestamp with time zone NOT NULL,
    schedule_revision bigint,
    scheduled_for timestamp with time zone,
    CONSTRAINT tenant_auto_profile_refresh_runs_available_nodes_check CHECK ((available_nodes >= 0)),
    CONSTRAINT tenant_auto_profile_refresh_runs_available_services_check CHECK ((available_services >= 0)),
    CONSTRAINT tenant_auto_profile_refresh_runs_check CHECK (((origin = 'scheduled'::text) = ((scheduled_for IS NOT NULL) AND (schedule_revision IS NOT NULL)))),
    CONSTRAINT tenant_auto_profile_refresh_runs_generation_check CHECK ((generation >= 0)),
    CONSTRAINT tenant_auto_profile_refresh_runs_origin_check CHECK ((origin = ANY (ARRAY['manual'::text, 'scheduled'::text]))),
    CONSTRAINT tenant_auto_profile_refresh_runs_status_check CHECK ((status = ANY (ARRAY['published'::text, 'unchanged'::text, 'unavailable'::text, 'disabled'::text])))
);


--
-- Name: tenant_auto_profile_refresh_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_auto_profile_refresh_schedules (
    tenant_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    daily_time text DEFAULT '12:00'::text NOT NULL,
    timezone text DEFAULT 'Europe/Moscow'::text NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    next_run_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_auto_profile_refresh_schedules_check CHECK ((enabled = (next_run_at IS NOT NULL))),
    CONSTRAINT tenant_auto_profile_refresh_schedules_daily_time_check CHECK ((daily_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'::text)),
    CONSTRAINT tenant_auto_profile_refresh_schedules_revision_check CHECK ((revision > 0)),
    CONSTRAINT tenant_auto_profile_refresh_schedules_timezone_check CHECK ((timezone = 'Europe/Moscow'::text))
);


--
-- Name: tenant_auto_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_auto_profiles (
    tenant_id uuid NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    name text DEFAULT 'Авто'::text NOT NULL,
    russia_direct boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    xray_network_policy text DEFAULT 'tunnel'::text NOT NULL,
    CONSTRAINT tenant_auto_profiles_name_check CHECK (((char_length(name) >= 1) AND (char_length(name) <= 80))),
    CONSTRAINT tenant_auto_profiles_xray_network_policy_check CHECK ((xray_network_policy = ANY (ARRAY['tunnel'::text, 'split_dns'::text])))
);


--
-- Name: tenant_branding; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_branding (
    tenant_id uuid NOT NULL,
    display_name text NOT NULL,
    tagline text DEFAULT ''::text NOT NULL,
    support_label text DEFAULT ''::text NOT NULL,
    support_url text DEFAULT ''::text NOT NULL,
    accent text DEFAULT 'blue'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_branding_accent_check CHECK ((accent = ANY (ARRAY['blue'::text, 'violet'::text, 'teal'::text, 'amber'::text, 'rose'::text]))),
    CONSTRAINT tenant_branding_display_name_check CHECK (((length(display_name) >= 1) AND (length(display_name) <= 80))),
    CONSTRAINT tenant_branding_support_label_check CHECK ((length(support_label) <= 40)),
    CONSTRAINT tenant_branding_support_url_check CHECK ((length(support_url) <= 500)),
    CONSTRAINT tenant_branding_tagline_check CHECK ((length(tagline) <= 160))
);


--
-- Name: tenant_resource_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_resource_limits (
    tenant_id uuid NOT NULL,
    max_clients integer DEFAULT 0 NOT NULL,
    max_plans integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_resource_limits_max_clients_check CHECK (((max_clients >= 0) AND (max_clients <= 100000))),
    CONSTRAINT tenant_resource_limits_max_plans_check CHECK (((max_plans >= 0) AND (max_plans <= 10000)))
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vpn_access_plan_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_access_plan_services (
    tenant_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    service_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vpn_access_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_access_plans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    code text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vpn_access_plans_code_format_chk CHECK (((code = lower(code)) AND (code ~ '^[a-z0-9][a-z0-9_-]{0,63}$'::text))),
    CONSTRAINT vpn_access_plans_code_not_empty_chk CHECK ((btrim(code) <> ''::text)),
    CONSTRAINT vpn_access_plans_name_not_empty_chk CHECK ((btrim(name) <> ''::text))
);


--
-- Name: vpn_cascades; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_cascades (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    plan_id uuid NOT NULL,
    entry_service_id uuid NOT NULL,
    exit_service_id uuid NOT NULL,
    entry_node_id uuid NOT NULL,
    exit_node_id uuid NOT NULL,
    entry_port integer NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    transit_uuid uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    connect_race_ip text DEFAULT ''::text NOT NULL,
    connect_race_attempts smallint DEFAULT 0 NOT NULL,
    connect_race_clients boolean DEFAULT false NOT NULL,
    CONSTRAINT vpn_cascade_client_dial_requires_policy CHECK (((NOT connect_race_clients) OR (connect_race_attempts > 0))),
    CONSTRAINT vpn_cascade_connect_race_bounded CHECK ((((connect_race_ip = ''::text) AND (connect_race_attempts = 0)) OR ((connect_race_ip <> ''::text) AND ((connect_race_attempts >= 2) AND (connect_race_attempts <= 16))))),
    CONSTRAINT vpn_cascades_check CHECK ((entry_node_id <> exit_node_id)),
    CONSTRAINT vpn_cascades_entry_port_check CHECK (((entry_port >= 1) AND (entry_port <= 65535) AND (entry_port <> 10085))),
    CONSTRAINT vpn_cascades_name_check CHECK (((length(btrim(name)) >= 1) AND (length(btrim(name)) <= 128)))
);


--
-- Name: vpn_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_services (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    name text NOT NULL,
    protocol text NOT NULL,
    listen text DEFAULT '0.0.0.0'::text NOT NULL,
    port integer NOT NULL,
    transport text NOT NULL,
    security text NOT NULL,
    public_address text,
    public_port integer,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    subscription_name text,
    CONSTRAINT vpn_services_listen_not_empty_chk CHECK ((btrim(listen) <> ''::text)),
    CONSTRAINT vpn_services_name_not_empty_chk CHECK ((btrim(name) <> ''::text)),
    CONSTRAINT vpn_services_port_chk CHECK (((port >= 1) AND (port <= 65535))),
    CONSTRAINT vpn_services_protocol_not_empty_chk CHECK ((btrim(protocol) <> ''::text)),
    CONSTRAINT vpn_services_public_endpoint_chk CHECK ((((public_address IS NULL) AND (public_port IS NULL)) OR ((public_address IS NOT NULL) AND (btrim(public_address) <> ''::text) AND (public_port >= 1) AND (public_port <= 65535)))),
    CONSTRAINT vpn_services_security_not_empty_chk CHECK ((btrim(security) <> ''::text)),
    CONSTRAINT vpn_services_subscription_name_check CHECK (((subscription_name IS NULL) OR ((char_length(btrim(subscription_name)) >= 1) AND (char_length(btrim(subscription_name)) <= 200) AND (subscription_name !~ '[[:cntrl:]]'::text)))),
    CONSTRAINT vpn_services_transport_not_empty_chk CHECK ((btrim(transport) <> ''::text))
);


--
-- Name: vpn_active_cascades; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vpn_active_cascades AS
 SELECT c.id,
    c.tenant_id,
    c.name,
    c.plan_id,
    c.entry_service_id,
    c.exit_service_id,
    c.entry_node_id,
    c.exit_node_id,
    c.entry_port,
    c.enabled,
    c.transit_uuid,
    c.created_at,
    c.updated_at,
    c.connect_race_ip,
    c.connect_race_attempts,
    c.connect_race_clients
   FROM (((((public.vpn_cascades c
     JOIN public.vpn_access_plans p ON (((p.id = c.plan_id) AND (p.tenant_id = c.tenant_id))))
     JOIN public.vpn_services a ON (((a.id = c.entry_service_id) AND (a.tenant_id = c.tenant_id) AND (a.node_id = c.entry_node_id))))
     JOIN public.vpn_services b ON (((b.id = c.exit_service_id) AND (b.tenant_id = c.tenant_id) AND (b.node_id = c.exit_node_id))))
     JOIN public.nodes an ON (((an.id = c.entry_node_id) AND (an.tenant_id = c.tenant_id))))
     JOIN public.nodes bn ON (((bn.id = c.exit_node_id) AND (bn.tenant_id = c.tenant_id))))
  WHERE (c.enabled AND p.enabled AND a.enabled AND b.enabled AND (an.status <> 'retired'::text) AND (bn.status <> 'retired'::text));


--
-- Name: vpn_bot_client_access_plans; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vpn_bot_client_access_plans AS
 SELECT DISTINCT b.tenant_id,
    b.client_id,
    s.plan_id
   FROM (((public.bot_accounts b
     JOIN public.bot_profiles p ON ((p.tenant_id = b.tenant_id)))
     JOIN public.bot_account_squads m ON (((m.tenant_id = b.tenant_id) AND (m.legacy_id = b.legacy_id))))
     JOIN public.bot_squads s ON (((s.tenant_id = m.tenant_id) AND (s.source_uuid = m.source_uuid))))
  WHERE ((b.client_id IS NOT NULL) AND (b.deleted_at IS NULL) AND b.source_present AND (p.activated_at IS NOT NULL) AND (p.state = ANY (ARRAY['active'::text, 'paused'::text])) AND s.source_present AND (s.plan_id IS NOT NULL));


--
-- Name: vpn_client_access_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_access_plans (
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vpn_client_continuous_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_continuous_quotas (
    client_id uuid NOT NULL,
    limit_bytes bigint NOT NULL,
    baseline_bytes bigint NOT NULL,
    baseline_at timestamp with time zone NOT NULL,
    uplink_bytes bigint DEFAULT 0 NOT NULL,
    downlink_bytes bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vpn_client_continuous_quotas_baseline_bytes_check CHECK (((baseline_bytes >= 0) AND (baseline_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT vpn_client_continuous_quotas_downlink_bytes_check CHECK (((downlink_bytes >= 0) AND (downlink_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT vpn_client_continuous_quotas_limit_bytes_check CHECK (((limit_bytes >= 0) AND (limit_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT vpn_client_continuous_quotas_uplink_bytes_check CHECK (((uplink_bytes >= 0) AND (uplink_bytes <= '9000000000000000'::bigint)))
);


--
-- Name: vpn_client_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_limits (
    client_id uuid NOT NULL,
    monthly_bytes bigint DEFAULT 0 NOT NULL,
    device_limit integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vpn_client_limits_device_limit_check CHECK (((device_limit >= 0) AND (device_limit <= 1000))),
    CONSTRAINT vpn_client_limits_monthly_bytes_check CHECK (((monthly_bytes >= 0) AND (monthly_bytes <= '9000000000000000'::bigint)))
);


--
-- Name: vpn_client_openvpn_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_openvpn_certificates (
    service_id uuid NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    credential_uuid uuid NOT NULL,
    serial text NOT NULL,
    certificate text NOT NULL,
    private_key text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT vpn_client_openvpn_certificates_serial_check CHECK ((serial ~ '^[1-9][0-9]{0,39}$'::text))
);


--
-- Name: vpn_client_pptp; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_pptp (
    service_id uuid NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    credential_uuid uuid NOT NULL,
    password text NOT NULL,
    address_index integer NOT NULL,
    CONSTRAINT vpn_client_pptp_address_index_check CHECK (((address_index >= 2) AND (address_index <= 253))),
    CONSTRAINT vpn_client_pptp_password_check CHECK ((password ~ '^[a-f0-9]{64}$'::text))
);


--
-- Name: vpn_client_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_services (
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    service_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vpn_client_shadowsocks_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_shadowsocks_keys (
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    credential_uuid uuid NOT NULL,
    client_key text NOT NULL,
    CONSTRAINT vpn_client_shadowsocks_keys_client_key_check CHECK ((length(client_key) = 44))
);


--
-- Name: vpn_client_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    token_id bytea NOT NULL,
    token_version bigint DEFAULT 1 NOT NULL,
    token_hash bytea NOT NULL,
    token_prefix text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_access_at timestamp with time zone,
    CONSTRAINT vpn_client_subscriptions_prefix_chk CHECK ((btrim(token_prefix) <> ''::text)),
    CONSTRAINT vpn_client_subscriptions_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text]))),
    CONSTRAINT vpn_client_subscriptions_token_hash_len_chk CHECK ((octet_length(token_hash) = 32)),
    CONSTRAINT vpn_client_subscriptions_token_id_len_chk CHECK ((octet_length(token_id) = 16)),
    CONSTRAINT vpn_client_subscriptions_version_chk CHECK ((token_version > 0))
);


--
-- Name: vpn_client_usage_monthly; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_usage_monthly (
    client_id uuid NOT NULL,
    period_start date NOT NULL,
    uplink_bytes bigint DEFAULT 0 NOT NULL,
    downlink_bytes bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vpn_client_usage_monthly_downlink_bytes_check CHECK (((downlink_bytes >= 0) AND (downlink_bytes <= '9000000000000000'::bigint))),
    CONSTRAINT vpn_client_usage_monthly_uplink_bytes_check CHECK (((uplink_bytes >= 0) AND (uplink_bytes <= '9000000000000000'::bigint)))
);


--
-- Name: vpn_client_wireguard; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_client_wireguard (
    service_id uuid NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    credential_uuid uuid NOT NULL,
    private_key text NOT NULL,
    public_key text NOT NULL,
    preshared_key text NOT NULL,
    address_index integer NOT NULL,
    CONSTRAINT vpn_client_wireguard_address_index_check CHECK (((address_index >= 2) AND (address_index <= 65534))),
    CONSTRAINT vpn_client_wireguard_preshared_key_check CHECK ((length(preshared_key) = 44)),
    CONSTRAINT vpn_client_wireguard_private_key_check CHECK ((length(private_key) = 44)),
    CONSTRAINT vpn_client_wireguard_public_key_check CHECK ((length(public_key) = 44))
);


--
-- Name: vpn_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    vless_uuid uuid DEFAULT gen_random_uuid() NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    remnawave_hold boolean DEFAULT false NOT NULL,
    registered_device_limit integer DEFAULT 0 NOT NULL,
    CONSTRAINT vpn_clients_name_not_empty_chk CHECK ((btrim(name) <> ''::text)),
    CONSTRAINT vpn_clients_registered_device_limit_check CHECK (((registered_device_limit >= 0) AND (registered_device_limit <= 1000))),
    CONSTRAINT vpn_clients_remnawave_hold_chk CHECK (((NOT remnawave_hold) OR (status = 'disabled'::text))),
    CONSTRAINT vpn_clients_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);


--
-- Name: vpn_effective_client_cascades; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vpn_effective_client_cascades AS
 WITH memberships AS (
         SELECT vpn_client_access_plans.tenant_id,
            vpn_client_access_plans.client_id,
            vpn_client_access_plans.plan_id
           FROM public.vpn_client_access_plans
        UNION
         SELECT billing_entitlements.tenant_id,
            billing_entitlements.client_id,
            billing_entitlements.plan_id
           FROM public.billing_entitlements
          WHERE (billing_entitlements.expires_at > now())
        UNION
         SELECT vpn_bot_client_access_plans.tenant_id,
            vpn_bot_client_access_plans.client_id,
            vpn_bot_client_access_plans.plan_id
           FROM public.vpn_bot_client_access_plans
        )
 SELECT k.tenant_id,
    c.id AS client_id,
    k.id AS cascade_id,
    k.entry_node_id
   FROM ((public.vpn_active_cascades k
     JOIN memberships m ON (((m.tenant_id = k.tenant_id) AND (m.plan_id = k.plan_id))))
     JOIN public.vpn_clients c ON (((c.id = m.client_id) AND (c.tenant_id = m.tenant_id))))
  WHERE ((c.status = 'active'::text) AND (NOT c.remnawave_hold) AND ((c.expires_at IS NULL) OR (c.expires_at > now())) AND (NOT public.vpn_client_quota_exceeded(c.id)));


--
-- Name: vpn_effective_client_services; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vpn_effective_client_services AS
 SELECT vpn_client_services.tenant_id,
    vpn_client_services.client_id,
    vpn_client_services.service_id
   FROM public.vpn_client_services
UNION
 SELECT cap.tenant_id,
    cap.client_id,
    aps.service_id
   FROM ((public.vpn_client_access_plans cap
     JOIN public.vpn_access_plans ap ON (((ap.id = cap.plan_id) AND (ap.tenant_id = cap.tenant_id))))
     JOIN public.vpn_access_plan_services aps ON (((aps.plan_id = cap.plan_id) AND (aps.tenant_id = cap.tenant_id))))
  WHERE ap.enabled
UNION
 SELECT be.tenant_id,
    be.client_id,
    aps.service_id
   FROM ((public.billing_entitlements be
     JOIN public.vpn_access_plans ap ON (((ap.id = be.plan_id) AND (ap.tenant_id = be.tenant_id))))
     JOIN public.vpn_access_plan_services aps ON (((aps.plan_id = be.plan_id) AND (aps.tenant_id = be.tenant_id))))
  WHERE (ap.enabled AND (be.expires_at > now()))
UNION
 SELECT cap.tenant_id,
    cap.client_id,
    aps.service_id
   FROM ((public.vpn_bot_client_access_plans cap
     JOIN public.vpn_access_plans ap ON (((ap.id = cap.plan_id) AND (ap.tenant_id = cap.tenant_id))))
     JOIN public.vpn_access_plan_services aps ON (((aps.plan_id = cap.plan_id) AND (aps.tenant_id = cap.tenant_id))))
  WHERE ap.enabled;


--
-- Name: vpn_service_amneziawg; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_amneziawg (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    version text NOT NULL,
    settings jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vpn_service_amneziawg_check CHECK (((jsonb_typeof((settings -> 'version'::text)) = 'string'::text) AND ((settings ->> 'version'::text) IS NOT NULL) AND ((settings ->> 'version'::text) = version))),
    CONSTRAINT vpn_service_amneziawg_settings_check CHECK (((jsonb_typeof(settings) = 'object'::text) AND (octet_length((settings)::text) <= 32768))),
    CONSTRAINT vpn_service_amneziawg_version_check CHECK ((version = ANY (ARRAY['1.0'::text, '1.5'::text, '2.0'::text, '3.0'::text, '3.1'::text])))
);


--
-- Name: vpn_service_openvpn; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_openvpn (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    ca_certificate text NOT NULL,
    ca_private_key text NOT NULL,
    server_certificate text NOT NULL,
    server_private_key text NOT NULL,
    tls_crypt_key text NOT NULL,
    next_refresh_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vpn_service_protocol_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_protocol_templates (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    template_id text NOT NULL,
    template_version text NOT NULL,
    request_key uuid NOT NULL,
    CONSTRAINT vpn_service_protocol_templates_template_id_check CHECK ((template_id = ANY (ARRAY['vless-reality-vision'::text, 'vless-tls-vision'::text, 'vless-xhttp-tls'::text, 'vless-ws-tls'::text, 'vless-grpc-tls'::text, 'trojan-tls'::text, 'shadowsocks-2022'::text, 'wireguard-xray'::text, 'wireguard-native'::text, 'amneziawg-mobile'::text, 'hysteria2-adaptive'::text, 'openvpn-udp'::text, 'openvpn-tcp'::text])))
);


--
-- Name: vpn_service_reality; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_reality (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    destination text NOT NULL,
    server_name text NOT NULL,
    fingerprint text DEFAULT 'chrome'::text NOT NULL,
    short_id text NOT NULL,
    secret_ref text NOT NULL,
    public_key text,
    public_key_observed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    legacy_server_names jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT vpn_service_reality_destination_chk CHECK ((btrim(destination) <> ''::text)),
    CONSTRAINT vpn_service_reality_fingerprint_chk CHECK ((btrim(fingerprint) <> ''::text)),
    CONSTRAINT vpn_service_reality_legacy_server_names_check CHECK (((jsonb_typeof(legacy_server_names) = 'array'::text) AND (jsonb_array_length(legacy_server_names) <= 2))),
    CONSTRAINT vpn_service_reality_public_key_chk CHECK (((public_key IS NULL) OR (btrim(public_key) <> ''::text))),
    CONSTRAINT vpn_service_reality_secret_ref_chk CHECK ((secret_ref ~ '^reality/[0-9a-f-]{36}$'::text)),
    CONSTRAINT vpn_service_reality_server_name_chk CHECK ((btrim(server_name) <> ''::text)),
    CONSTRAINT vpn_service_reality_short_id_chk CHECK ((short_id ~ '^([0-9a-f]{2}){0,8}$'::text))
);


--
-- Name: vpn_service_shadowsocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_shadowsocks (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    server_key text NOT NULL,
    CONSTRAINT vpn_service_shadowsocks_server_key_check CHECK ((length(server_key) = 44))
);


--
-- Name: vpn_service_tls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_tls (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    node_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vpn_service_wireguard; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vpn_service_wireguard (
    service_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    private_key text NOT NULL,
    public_key text NOT NULL,
    CONSTRAINT vpn_service_wireguard_private_key_check CHECK ((length(private_key) = 44)),
    CONSTRAINT vpn_service_wireguard_public_key_check CHECK ((length(public_key) = 44))
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    endpoint_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_until timestamp with time zone,
    lease_token uuid,
    last_http_status integer,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT webhook_deliveries_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT webhook_deliveries_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'delivering'::text, 'delivered'::text, 'failed'::text, 'cancelled'::text])))
);


--
-- Name: webhook_dispatcher_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_dispatcher_runs (
    id boolean DEFAULT true NOT NULL,
    last_success_at timestamp with time zone NOT NULL,
    CONSTRAINT webhook_dispatcher_runs_id_check CHECK (id)
);


--
-- Name: webhook_endpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_endpoints (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    events text[] NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    secret_ciphertext text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT webhook_endpoints_events_check CHECK (((cardinality(events) >= 1) AND (cardinality(events) <= 2) AND (events <@ ARRAY['billing.invoice_paid'::text, 'billing.invoice_voided'::text]))),
    CONSTRAINT webhook_endpoints_name_check CHECK (((length(name) >= 1) AND (length(name) <= 100))),
    CONSTRAINT webhook_endpoints_url_check CHECK ((length(url) <= 1000))
);


--
-- Name: remnawave_inventory_revisions sequence_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.remnawave_inventory_revisions ALTER COLUMN sequence_id SET DEFAULT nextval('public.remnawave_inventory_revisions_sequence_id_seq'::regclass);


--
-- PostgreSQL database dump complete
--
