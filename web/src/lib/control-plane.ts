import "server-only";
import type { Cascade, CascadeInput, CascadeMutation } from "@/lib/cascades";
export async function getCascades(tenant: string) { return (await cpFetch<{ cascades: Cascade[] }>(`/api/v1/tenants/${encodeURIComponent(tenant)}/cascades`)).cascades; }
export function getCascade(id: string) { return cpFetch<Cascade>(`/api/v1/vpn-cascades/${encodeURIComponent(id)}`); }
export function saveCascade(tenant: string, id: string | null, body: CascadeInput) { return cpFetch<CascadeMutation>(id ? `/api/v1/vpn-cascades/${encodeURIComponent(id)}` : `/api/v1/tenants/${encodeURIComponent(tenant)}/cascades`, { method: id ? "PUT" : "POST", body, timeoutMs: 35_000 }); }
export function deleteCascade(id: string) { return cpFetch<CascadeMutation>(`/api/v1/vpn-cascades/${encodeURIComponent(id)}`, { method: "DELETE", timeoutMs: 35_000 }); }
import type { RegisteredDevices } from "@/lib/client-devices";
export function getRegisteredDevices(id: string) { return cpFetch<RegisteredDevices>(`/api/v1/vpn-clients/${encodeURIComponent(id)}/devices`); }
export function setRegisteredDeviceLimit(id: string, limit: number) { return cpFetch<RegisteredDevices>(`/api/v1/vpn-clients/${encodeURIComponent(id)}/device-limit`, { method: "PUT", body: { limit } }); }
export function deleteRegisteredDevice(id: string, deviceID: string) { return cpFetch<RegisteredDevices>(`/api/v1/vpn-clients/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceID)}`, { method: "DELETE" }); }
export function deleteNode(id: string, confirmName: string, options: { serverStopped: boolean; decommissionOnline: boolean }) { return cpFetch<{ deleted: boolean; decommissioning?: boolean; generation?: number; node_id: string; deleted_at?: string }>(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: "DELETE", body: { confirm_name: confirmName, server_stopped: options.serverStopped, decommission_online: options.decommissionOnline }, timeoutMs: 35_000 }); }
export function renameNode(id: string, name: string) { return cpFetch<{ node_id: string; name: string; changed: boolean }>(`/api/v1/nodes/${encodeURIComponent(id)}`, { method: "PATCH", body: { name }, timeoutMs: 15_000 }); }
export function requestNodeReboot(id: string, confirmName: string) { return cpFetch<{ queued: boolean; delay_seconds: number; job: { id: string; node_id: string; node_name: string; status: string; created_at: string } }>(`/api/v1/nodes/${encodeURIComponent(id)}/reboot`, { method: "POST", body: { confirm_name: confirmName, confirm_reboot: true }, timeoutMs: 15_000 }); }
import type { AgentFleetStatus } from "@/lib/update-types";
export function getAgentFleetStatus() { return cpFetch<AgentFleetStatus>("/api/v1/agent-updates"); }
export function startAgentFleet(node: string, requestKey: string) { return cpFetch<{ run_id: string }>(`/api/v1/nodes/${encodeURIComponent(node)}/agent-update`, { method: "POST", body: { request_key: requestKey } }); }
export function pauseAgentFleet(id: string, paused: boolean) { return cpFetch<void>(`/api/v1/agent-updates/${encodeURIComponent(id)}/pause`, { method: "POST", body: { paused } }); }
export function retryAgentUpdate(id: string) { return cpFetch<void>(`/api/v1/agent-update-jobs/${encodeURIComponent(id)}/retry`, { method: "POST" }); }
export function importLatestXray() { return cpFetch<{ release: CoreRelease }>("/api/v1/core-releases/import/xray/latest", { method: "POST", timeoutMs: 60_000 }); }
export function approveXrayRelease(id: string) { return cpFetch<void>(`/api/v1/core-releases/${encodeURIComponent(id)}/approve`, { method: "POST" }); }
export function startXrayUpdate(node: string, release: string, requestKey: string, acceptPrerelease: boolean) { return cpFetch<{ plan_id: string; target_version: string; generation: number }>(`/api/v1/nodes/${encodeURIComponent(node)}/xray-update`, { method: "POST", body: { release_id: release, request_key: requestKey, accept_prerelease: acceptPrerelease }, timeoutMs: 30_000 }); }
import { clientListMetadata, type ClientListRecord } from "@/lib/client-list-metadata";
import type { RemnawaveImport, RemnawaveImportClient } from "@/lib/remnawave-types";
export function deleteVPNClient(id: string, confirmName: string) { return cpFetch<{ deleted: boolean; client_id: string }>(`/api/v1/vpn-clients/${encodeURIComponent(id)}`, { method: "DELETE", body: { confirm_name: confirmName }, timeoutMs: 30_000 }); }
export async function getRemnawaveImports() { return (await cpFetch<{ imports: RemnawaveImport[] }>("/api/v1/remnawave/imports")).imports; }
export function getRemnawaveImportClients(id: string, after: number) { return cpFetch<{ clients: RemnawaveImportClient[]; next_cursor: number | null }>(`/api/v1/remnawave/imports/${encodeURIComponent(id)}/clients?after=${after}`); }
export function importReviewedWireGuard(){return cpFetch<{created:boolean;release:CoreRelease}>("/api/v1/core-releases/wireguard/import-reviewed",{method:"POST"});}
export function approveReviewedWireGuard(){return cpFetch<{approved:boolean}>("/api/v1/core-releases/wireguard/approve-reviewed",{method:"POST"});}
export function initializeWireGuard(id:string){return cpFetch<{generation:number;changed:boolean}>(`/api/v1/nodes/${encodeURIComponent(id)}/initialize-wireguard`,{method:"POST"});}
export function importReviewedPPTP(){return cpFetch<{created:boolean;release:CoreRelease}>("/api/v1/core-releases/pptp/import-reviewed",{method:"POST"});}
export function approveReviewedPPTP(){return cpFetch<{approved:boolean}>("/api/v1/core-releases/pptp/approve-reviewed",{method:"POST"});}
export function initializePPTP(id:string){return cpFetch<{generation:number;changed:boolean}>(`/api/v1/nodes/${encodeURIComponent(id)}/initialize-pptp`,{method:"POST"});}
export function rotatePPTPCredential(service:string,client:string){return cpFetch<{generation:number;changed:boolean}>(`/api/v1/vpn-services/${encodeURIComponent(service)}/pptp-clients/${encodeURIComponent(client)}/rotate-credential`,{method:"POST"});}
export function importReviewedOpenVPN(){return cpFetch<{created:boolean;release:CoreRelease}>("/api/v1/core-releases/openvpn/import-reviewed",{method:"POST"});}
export function approveReviewedOpenVPN(){return cpFetch<{approved:boolean}>("/api/v1/core-releases/openvpn/approve-reviewed",{method:"POST"});}
export function initializeOpenVPN(id:string){return cpFetch<{generation:number;changed:boolean}>(`/api/v1/nodes/${encodeURIComponent(id)}/initialize-openvpn`,{method:"POST"});}
export function importReviewedHysteria(){return cpFetch<{created:boolean;release:CoreRelease}>("/api/v1/core-releases/hysteria2/import-reviewed",{method:"POST"});}
export function approveReviewedHysteria(){return cpFetch<{approved:boolean}>("/api/v1/core-releases/hysteria2/approve-reviewed",{method:"POST"});}
export function initializeHysteria(id:string){return cpFetch<{generation:number;changed:boolean}>(`/api/v1/nodes/${encodeURIComponent(id)}/initialize-hysteria`,{method:"POST"});}
export function initializeXray(id:string){return cpFetch<{node_id:string;generation:number;changed:boolean;core_type:string;version:string}>(`/api/v1/nodes/${encodeURIComponent(id)}/initialize-xray`,{method:"POST"});}
import type { NodeRuntime } from "@/lib/node-runtime";
import { adminAuthorization } from "@/lib/auth";
import type { AdminAccount, AdminRole } from "@/lib/admin-types";
export async function getOwnAdminSessions() { return (await cpFetch<{ sessions: import("@/lib/admin-types").AdminSessionInfo[] }>("/api/v1/admin/me/sessions")).sessions; }
export function revokeOwnAdminSession(id: string | null) { return cpFetch<void>(`/api/v1/admin/me/sessions${id ? `/${encodeURIComponent(id)}` : ""}`, { method: "DELETE" }); }
export async function getAdminAccounts() { return (await cpFetch<{ accounts: AdminAccount[] }>("/api/v1/admin/accounts")).accounts; }
export function createAdminAccount(body: { username: string; role: AdminRole; password: string }) { return cpFetch<AdminAccount>("/api/v1/admin/accounts", { method: "POST", body }); }
export function updateAdminAccount(id: string, body: { role?: AdminRole; enabled?: boolean }) { return cpFetch<AdminAccount>(`/api/v1/admin/accounts/${encodeURIComponent(id)}`, { method: "PATCH", body }); }
export function resetAdminPassword(id: string, password: string) { return cpFetch<AdminAccount>(`/api/v1/admin/accounts/${encodeURIComponent(id)}/password`, { method: "PUT", body: { password } }); }
export function changeAdminPassword(current_password: string, new_password: string) { return cpFetch<void>("/api/v1/admin/me/password", { method: "PUT", body: { current_password, new_password } }); }
import type { BillingOffer, BillingInvoice } from "@/lib/billing-values";

export async function getBillingOffers(tenant: string) { return (await cpFetch<{ offers: BillingOffer[] }>(`/api/v1/tenants/${encodeURIComponent(tenant)}/billing/offers`)).offers; }
export async function getBillingInvoices(tenant: string) { return (await cpFetch<{ invoices: BillingInvoice[] }>(`/api/v1/tenants/${encodeURIComponent(tenant)}/billing/invoices`)).invoices; }
export function saveBillingOffer(tenant: string, id: string | null, body: { plan_id?: string; name: string; amount_minor: number; currency: string; duration_days: number; enabled: boolean }) { return cpFetch<BillingOffer>(id ? `/api/v1/billing/offers/${encodeURIComponent(id)}` : `/api/v1/tenants/${encodeURIComponent(tenant)}/billing/offers`, { method: id ? "PUT" : "POST", body }); }
export function createBillingInvoice(tenant: string, body: { offer_id: string; client_id: string }, key: string) { return cpFetch<BillingInvoice>(`/api/v1/tenants/${encodeURIComponent(tenant)}/billing/invoices`, { method: "POST", body, idempotencyKey: key }); }
export function billingInvoiceAction(id: string, operation: "settle" | "void", reference?: string) { return cpFetch<unknown>(`/api/v1/billing/invoices/${encodeURIComponent(id)}/${operation}`, { method: "POST", body: operation === "settle" ? { payment_reference: reference, payment_received: true } : {} }); }
export function getBillingIntegrationStatus() { return cpFetch<{ payment_webhook_enabled: boolean; automatic_payment_capture: boolean }>("/api/v1/billing/integration-status"); }

export type TenantAPICredential = { id: string; tenant_id: string; name: string; role: "viewer" | "operator" | "reseller"; created_at: string; expires_at: string; revoked_at: string | null; last_used_at: string | null };
export async function getTenantAPICredentials(tenant: string) { return (await cpFetch<{ credentials: TenantAPICredential[] }>(`/api/v1/tenants/${encodeURIComponent(tenant)}/api-tokens`)).credentials; }
export function createTenantAPICredential(tenant: string, body: { name: string; role: string; expires_at: string }) { return cpFetch<{ credential: TenantAPICredential; token: string }>(`/api/v1/tenants/${encodeURIComponent(tenant)}/api-tokens`, { method: "POST", body }); }
export function revokeTenantAPICredential(id: string) { return cpFetch<TenantAPICredential>(`/api/v1/tenant-api-tokens/${encodeURIComponent(id)}/revoke`, { method: "POST", body: {} }); }

export type BackupStatus = { id: string; status: string; last_success_at: string | null; last_verified_at: string | null; size_bytes: number; verification: string; free_bytes: number; reported_at?: string };
export type OperationsStatus = {
  restore_drill: { status: "verified" | "failed"; backup_id: string; verified_at: string | null; checked_at: string | null; control_plane_version: string; web_pages: number; duration_seconds: number } | null;
  pending_access_nodes: number;
  generated_at: string; control_plane_backup: BackupStatus | null; control_plane_free_bytes: number;
  expiring_certificates: number; expired_certificates: number; failed_certificates: number; attention_certificates: number;
  nodes: { id: string; name: string; lifecycle: { registered: boolean; online: boolean; healthy: boolean; health_fresh: boolean; agent_version?: string; desired_generation: number; applied_generation: number }; backup: BackupStatus | null; traffic_delivery?: { sequence: number; recorded_at: string | null; received_at: string | null } }[];
};
export function getOperationsStatus() { return cpFetch<OperationsStatus>("/api/v1/operations/status"); }
export function updateVPNClientLifecycle(id: string, body: { name?: string; status?: string; expires_at?: string; clear_expires_at?: boolean }) { return cpFetch<VPNClientRecord>(`/api/v1/vpn-clients/${encodeURIComponent(id)}`, { method: "PATCH", body }); }

export type VPNServiceTLS = { service_id: string; certificate_id: string; server_name: string };
export function getVPNServiceTLS(id: string) { return cpFetch<VPNServiceTLS>(`/api/v1/vpn-services/${encodeURIComponent(id)}/tls`); }
export function configureVPNServiceTLS(id: string, certificate: string) {
  return cpFetch<{ tls: VPNServiceTLS; generation: number }>(`/api/v1/vpn-services/${encodeURIComponent(id)}/tls`, { method: "PUT", body: { certificate_id: certificate } });
}

export type NodeCertificate = {
  id: string; node_id: string; tenant_id: string; domain: string;
  environment: "staging" | "production"; status: string; auto_renew: boolean;
  issuer?: string; fingerprint_sha256?: string; not_after?: string; last_error?: string;
};
export type CertificateJob = { id: string; operation: string; status: string; created_at: string };
export async function getNodeCertificates(node: string) {
  return (await cpFetch<{ certificates: NodeCertificate[] }>(`/api/v1/nodes/${encodeURIComponent(node)}/certificates`)).certificates;
}
export async function getTLSCertificates(node: string) {
  const now = Date.now();
  return (await getNodeCertificates(node)).filter(c => c.environment === "production" && ["active", "renewing"].includes(c.status) && c.not_after && Date.parse(c.not_after) > now).map(c => ({ id: c.id, domain: c.domain }));
}
export async function getCertificateJobs(id: string) {
  return (await cpFetch<{ jobs: CertificateJob[] }>(`/api/v1/certificates/${encodeURIComponent(id)}/jobs`)).jobs;
}
export async function createNodeCertificate(node: string, body: { domain: string; environment: string; auto_renew: boolean; contact_email?: string }) {
  return cpFetch<NodeCertificate>(`/api/v1/nodes/${encodeURIComponent(node)}/certificates`, { method: "POST", body });
}
export async function certificateOperation(id: string, operation: "issue" | "renew" | "archive" | "auto-renew" | "delete", enabled?: boolean, confirmDomain?: string) {
    return cpFetch<unknown>(`/api/v1/certificates/${encodeURIComponent(id)}${operation === "auto-renew" || operation === "delete" ? "" : `/${operation}`}`, {
      method: operation === "auto-renew" ? "PATCH" : operation === "delete" ? "DELETE" : "POST", body: operation === "auto-renew" ? { auto_renew: enabled } : operation === "delete" ? { confirm_domain: confirmDomain } : {},
  });
}

export type AccessPlan = {
  id: string; tenant_id: string; name: string; code: string; enabled: boolean;
  created_at: string; updated_at: string;
};
export type AccessPlanDetail = AccessPlan & { service_ids: string[]; client_ids: string[]; bot_client_ids?: string[] };
export type AccessPlanMutation = { changed: boolean; rebuilds: { node_id: string; generation: number }[] };
export async function getAccessPlans(tenantID: string) {
  return (await cpFetch<{ plans: AccessPlan[] }>(`/api/v1/tenants/${encodeURIComponent(tenantID)}/access-plans`)).plans;
}
export async function getAccessPlan(id: string) {
  return cpFetch<AccessPlanDetail>(`/api/v1/access-plans/${encodeURIComponent(id)}`);
}
export async function createAccessPlan(tenantID: string, body: { name: string; code: string; enabled: boolean }) {
  return cpFetch<AccessPlan>(`/api/v1/tenants/${encodeURIComponent(tenantID)}/access-plans`, { method: "POST", body });
}
export async function mutateAccessPlan(id: string, method: "PATCH" | "DELETE" | "POST", suffix = "", body?: unknown) {
  return cpFetch<AccessPlanMutation>(`/api/v1/access-plans/${encodeURIComponent(id)}${suffix}`, { method, body });
}

const BASE_URL =
  process.env.CONTROL_PLANE_URL ??
  "http://127.0.0.1:8080";

export class ControlPlaneError extends Error {
  status: number;
  body: string;

  constructor(
    status: number,
    body: string
  ) {
    super(
      body ||
        `Control Plane HTTP ${status}`
    );

    this.name =
      "ControlPlaneError";

    this.status =
      status;

    this.body =
      body;
  }
}

export class ControlPlaneTimeoutError extends Error {
  constructor() {
    super("Контур управления не ответил вовремя. Повторите запрос подключения.");
    this.name = "ControlPlaneTimeoutError";
  }
}

async function cpFetch<T>(
  path: string,
  options: {
    authenticated?: boolean;
    method?: string;
    body?: unknown;
    idempotencyKey?: string;
    timeoutMs?: number;
  } = {}
): Promise<T> {
  const authenticated =
    options.authenticated ??
    true;

  const method =
    options.method ??
    "GET";

  const headers:
    Record<string, string> = {
      Accept:
        "application/json",
  };

  if (authenticated) {
    headers.Authorization =
      `Bearer ${await adminAuthorization()}`;
  }

  let body:
    // Request identity is sent separately from immutable invoice fields.
    string |
    undefined;
  if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey;

  if (
    options.body !==
    undefined
  ) {
    headers["Content-Type"] =
      "application/json";

    body =
      JSON.stringify(
        options.body
      );
  }

  const signal = options.timeoutMs === undefined
    ? undefined
    : AbortSignal.timeout(options.timeoutMs);
  let response: Response;
  let text: string;

  try {
    response = await fetch(
      `${BASE_URL}${path}`,
      {
        method,
        headers,
        body,
        cache:
          "no-store",
        signal,
      }
    );

    // The same deadline includes response body delivery, not only headers.
    text = await response.text();
  } catch (error) {
    if (signal?.aborted) throw new ControlPlaneTimeoutError();
    throw error;
  }

  if (!response.ok) {
    let message =
      text;

    try {
      const parsed =
        JSON.parse(text) as {
          error?: string;
        };

      if (parsed.error) {
        message =
          parsed.error;
      }
    } catch {
      // Keep raw body.
    }

    throw new ControlPlaneError(
      response.status,
      message
    );
  }

  if (!text) {
    return undefined as T;
  }

  return JSON.parse(text) as T;
}

export type NodeRecord = {
  runtime_core?: NodeRuntime;
  id: string;
  tenant_id: string;
  name: string;
  status: string;
  agent_version?: string;
  os_name?: string;
  os_version?: string;
  architecture?: string;
  desired_generation: number;
  applied_generation: number;
  last_seen_at?: string;
  created_at: string;
};

export type Lifecycle = {
  runtime_core?: NodeRuntime;
  node_id: string;
  state: string;
  online: boolean;
  registered: boolean;
  bootstrap_consumed: boolean;
  agent_version?: string;
  os_name?: string;
  os_version?: string;
  architecture?: string;
  desired_generation: number;
  applied_generation: number;
  generation_drift: number;
  health_present: boolean;
  health_fresh: boolean;
  healthy: boolean;
  current_core_version?: string;
  last_known_good_core_version?: string;
  rollback_ready: boolean;
  latest_deployment_generation?: number;
  latest_deployment_status?: string;
  active_recovery: boolean;
  last_seen_at?: string;
  health_checked_at?: string;
};

export type Runtime = {
  node_id: string;
  node_status: string;
  health_present: boolean;
  healthy: boolean;
  desired_generation: number;
  applied_generation: number;
  health_applied_generation: number;
  current_core_version?: string;
  last_known_good_core_version?: string;
  snapshot_count: number;
  latest_snapshot_id?: string;
  rollback_ready: boolean;
  checked_at?: string;
};

export type NodeDetail = {
  node: NodeRecord;
  runtime: Runtime;
  lifecycle: Lifecycle;
};

export type NodeMetricPoint = {
  sampled_at: string;
  cpu_percent: number;
  load_1: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  network_rx_bytes: number;
  network_tx_bytes: number;
  uptime_seconds: number;
};

export type NodeMetricSeries = {
  node_id: string;
  from: string;
  to: string;
  step_seconds: number;
  points: NodeMetricPoint[];
};

export type DiagnosticCheck = {
  code: string;
  status: string;
  message: string;
};

export type Diagnostics = {
  node_id: string;
  lifecycle_state: string;
  overall: string;
  checks: DiagnosticCheck[];
  generated_at: string;
};

export type Deployment = {
  id: string;
  node_id: string;
  generation: number;
  status: string;
  previous_core_version?: string;
  requested_core_version?: string;
  applied_core_version?: string;
  error_message?: string;
  core_release_id?: string;
  core_type?: string;
  started_at?: string;
  completed_at?: string;
  updated_at?: string;
};

export type CoreRelease = {
  id?: string;
  type?: string;
  core_type?: string;
  version: string;
  os?: string;
  architecture?: string;
  channel?: string;
  approved?: boolean;
  revoked?: boolean;
  upstream_prerelease?: boolean;
  created_at?: string;
};

export type RolloutPlan = {
  id: string;
  node_id?: string;
  status?: string;
  core_type?: string;
  source_version?: string;
  current_version?: string;
  candidate_version?: string;
  target_version?: string;
  target_channel?: string;
  blockers?: string[];
  [key: string]: unknown;
};

export type RecoveryAttempt = {
  id: string;
  node_id?: string;
  status?: string;
  source_generation?: number;
  proposed_generation?: number;
  target_version?: string;
  target_core_version?: string;
  blockers?: string[];
  [key: string]: unknown;
};

export type RecoveryEvaluation = {
  recovery_needed?: boolean;
  recommended_action?: string;
  automatic_allowed?: boolean;
  blockers?: string[];
  [key: string]: unknown;
};

export type CoreUpdateEvaluation = {
  allowed?: boolean;
  update_available?: boolean;
  current_version?: string;
  candidate_version?: string;
  target_version?: string;
  blockers?: string[];
  [key: string]: unknown;
};

export async function getControlPlaneHealth() {
  return cpFetch<{
    service: string;
    status: string;
    version: string;
  }>(
    "/healthz",
    {
      authenticated:
        false,
    }
  );
}

export async function getNodes(deleted = false):
  Promise<NodeRecord[]> {
  const data =
    await cpFetch<unknown>(
      deleted ? "/api/v1/nodes?deleted=true" : "/api/v1/nodes"
    );

  if (Array.isArray(data)) {
    return data as NodeRecord[];
  }

  if (
    data &&
    typeof data ===
      "object" &&
    Array.isArray(
      (
        data as {
          nodes?: unknown;
        }
      ).nodes
    )
  ) {
    return (
      data as {
        nodes:
          NodeRecord[];
      }
    ).nodes;
  }

  return [];
}

export function getNode(
  id: string
) {
  return cpFetch<NodeDetail>(
    `/api/v1/nodes/${id}`
  );
}

export function getNodeMetrics(
  id: string,
  range: "1h" | "24h" | "7d" | "30d" = "24h"
) {
  return cpFetch<NodeMetricSeries>(
    `/api/v1/nodes/${encodeURIComponent(id)}/metrics?range=${range}`
  );
}

export function getLifecycle(
  id: string
) {
  return cpFetch<Lifecycle>(
    `/api/v1/nodes/${id}/lifecycle`
  );
}

export function getDiagnostics(
  id: string
) {
  return cpFetch<Diagnostics>(
    `/api/v1/nodes/${id}/diagnostics`
  );
}

export async function getDeployments(
  id: string
): Promise<Deployment[]> {
  const data =
    await cpFetch<unknown>(
      `/api/v1/nodes/${id}/deployments`
    );

  if (Array.isArray(data)) {
    return data as Deployment[];
  }

  if (
    data &&
    typeof data ===
      "object" &&
    Array.isArray(
      (
        data as {
          deployments?: unknown;
        }
      ).deployments
    )
  ) {
    return (
      data as {
        deployments:
          Deployment[];
      }
    ).deployments;
  }

  return [];
}

export async function getCoreReleases():
  Promise<CoreRelease[]> {
  const data =
    await cpFetch<unknown>(
      "/api/v1/core-releases"
    );

  if (Array.isArray(data)) {
    return data as CoreRelease[];
  }

  if (
    data &&
    typeof data ===
      "object"
  ) {
    const object =
      data as {
        releases?: CoreRelease[];
        core_releases?: CoreRelease[];
      };

    return (
      object.releases ??
      object.core_releases ??
      []
    );
  }

  return [];
}

export function getCoreUpdateStatus(
  nodeID: string,
  coreType = "xray"
) {
  return cpFetch<
    Record<string, unknown>
  >(
    `/api/v1/nodes/${nodeID}/core-update-status?core=${encodeURIComponent(coreType)}`
  );
}

export function evaluateCoreUpdate(
  nodeID: string,
  version: string,
  coreType = "xray"
) {
  return cpFetch<
    CoreUpdateEvaluation
  >(
    `/api/v1/nodes/${nodeID}/core-update-evaluate?core=${encodeURIComponent(coreType)}&version=${encodeURIComponent(version)}`
  );
}

export function createRolloutPlan(
  nodeID: string,
  coreType = "xray"
) {
  return cpFetch<RolloutPlan>(
    `/api/v1/nodes/${nodeID}/rollout-plans`,
    {
      method:
        "POST",

      body: {
        core_type:
          coreType,
      },
    }
  );
}

export function getRolloutPlan(
  planID: string
) {
  return cpFetch<RolloutPlan>(
    `/api/v1/rollout-plans/${planID}`
  );
}

export function approveRolloutPlan(
  planID: string
) {
  return cpFetch<RolloutPlan>(
    `/api/v1/rollout-plans/${planID}/approve`,
    {
      method:
        "POST",
    }
  );
}

function unwrapPlan(
  value:
    RolloutPlan |
    {
      plan: RolloutPlan;
      changed?: boolean;
    }
): RolloutPlan {
  const wrapped =
    value as {
      plan?: RolloutPlan;
    };

  if (
    wrapped.plan &&
    typeof wrapped.plan.id ===
      "string" &&
    wrapped.plan.id !== ""
  ) {
    return wrapped.plan;
  }

  return value as RolloutPlan;
}

export async function executeRolloutPlan(
  planID: string
) {
  const value =
    await cpFetch<
      RolloutPlan |
      {
        plan:
          RolloutPlan;
        changed?: boolean;
      }
    >(
      `/api/v1/rollout-plans/${planID}/execute`,
      {
        method:
          "POST",
      }
    );

  return unwrapPlan(value);
}

export async function cancelRolloutPlan(
  planID: string
) {
  const value =
    await cpFetch<
      RolloutPlan |
      {
        plan:
          RolloutPlan;
        changed?: boolean;
      }
    >(
      `/api/v1/rollout-plans/${planID}/cancel`,
      {
        method:
          "POST",
      }
    );

  return unwrapPlan(value);
}

export function getRecoveryEvaluation(
  nodeID: string,
  generation: number
) {
  return cpFetch<
    RecoveryEvaluation
  >(
    `/api/v1/nodes/${nodeID}/deployments/${generation}/recovery-evaluation`
  );
}

function unwrapRecoveryAttempt(
  value: {
    recovery_attempt:
      RecoveryAttempt;
    changed?: boolean;
  }
): RecoveryAttempt {
  return value.recovery_attempt;
}

export async function createRecoveryAttempt(
  nodeID: string,
  generation: number
) {
  const value =
    await cpFetch<{
      recovery_attempt:
        RecoveryAttempt;
    }>(
      `/api/v1/nodes/${nodeID}/deployments/${generation}/recovery-attempts`,
      {
        method:
          "POST",
      }
    );

  return unwrapRecoveryAttempt(
    value
  );
}

export async function approveRecoveryAttempt(
  attemptID: string
) {
  const value =
    await cpFetch<{
      recovery_attempt:
        RecoveryAttempt;
    }>(
      `/api/v1/recovery-attempts/${attemptID}/approve`,
      {
        method:
          "POST",
      }
    );

  return unwrapRecoveryAttempt(
    value
  );
}

export async function executeRecoveryAttempt(
  attemptID: string
) {
  const value =
    await cpFetch<{
      recovery_attempt:
        RecoveryAttempt;
      changed?: boolean;
    }>(
      `/api/v1/recovery-attempts/${attemptID}/execute`,
      {
        method:
          "POST",
      }
    );

  return unwrapRecoveryAttempt(
    value
  );
}

export async function cancelRecoveryAttempt(
  attemptID: string
) {
  const value =
    await cpFetch<{
      recovery_attempt:
        RecoveryAttempt;
      changed?: boolean;
    }>(
      `/api/v1/recovery-attempts/${attemptID}/cancel`,
      {
        method:
          "POST",
      }
    );

  return unwrapRecoveryAttempt(
    value
  );
}

export type CreateNodeResponse = {
  node: NodeRecord;
  bootstrap_token: string;
  bootstrap_token_note?: string;
};

export async function createNode(
  tenantID: string,
  name: string,
  runtime: NodeRuntime = "xray"
) {
  return cpFetch<CreateNodeResponse>(
    "/api/v1/nodes",
    {
      method: "POST",
      body: {
        tenant_id: tenantID,
        name,
        runtime_core: runtime,
      },
    }
  );
}

export type TenantRecord = {
  id: string;
  name: string;
  created_at: string;
};

export async function getTenants() {
  const response =
    await cpFetch<{
      tenants: TenantRecord[];
    }>(
      "/api/v1/tenants"
    );

  return response.tenants;
}

export type VPNClientRecord = ClientListRecord;

export type VPNClientUsage = {
  client_id: string;
  period_start: string;
  uplink_bytes: number;
  downlink_bytes: number;
  used_bytes: number;
  monthly_limit_bytes: number;
  traffic_limit_bytes?: number;
  reset_policy?: "MONTH" | "NO_RESET";
  imported_bytes?: number;
  remaining_bytes: number;
  quota_exceeded: boolean;
  active_ips: number | null;
  device_limit: number;
  device_warning: boolean;
  last_observed_at?: string | null;
  updated_at: string;
};

export function getVPNClientUsage(id: string) {
  return cpFetch<VPNClientUsage>(`/api/v1/vpn-clients/${encodeURIComponent(id)}/usage`);
}

export function saveVPNClientLimits(id: string, monthlyBytes: number, deviceLimit: number) {
  return cpFetch<VPNClientUsage>(`/api/v1/vpn-clients/${encodeURIComponent(id)}/limits`, {
    method: "PUT",
    body: { monthly_bytes: monthlyBytes, device_limit: deviceLimit },
  });
}

export function saveVPNClientContinuousLimit(id: string, limitBytes: number) {
  return cpFetch<VPNClientUsage>(`/api/v1/vpn-clients/${encodeURIComponent(id)}/continuous-limit`, {
    method: "PUT", body: { limit_bytes: limitBytes },
  });
}

export type VPNServiceRecord = {
  id: string;
  tenant_id: string;
  node_id: string;
  name: string;
  subscription_name?: string | null;
  subscription_default_name?: string;
  protocol: string;
  listen: string;
  port: number;
  transport: string;
  security: string;
  public_address?: string | null;
  public_port?: number | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type VPNClientConnection = {
  client_id: string;
  client_name: string;
  service_id: string;
  service_name: string;
  address: string;
  port: number;
  runtime_core?: NodeRuntime;
  amneziawg_version?: string;
  protocol: string;
  transport: string;
  security: string;
  uuid: string;
  server_name: string;
  fingerprint: string;
  short_id: string;
  password: string;
  uri?: string;
  config?: string;
  config_filename?: string;
  config_expires_at?: string;
};

export async function getVPNClients(
  tenantID: string
): Promise<VPNClientRecord[]> {
  const data =
    await cpFetch<unknown>(
      `/api/v1/tenants/${tenantID}/vpn-clients`
    );

  if (Array.isArray(data)) {
    return (data as VPNClientRecord[]).map(clientListMetadata);
  }

  if (
    data &&
    typeof data === "object" &&
    Array.isArray(
      (
        data as {
          clients?: unknown;
        }
      ).clients
    )
  ) {
    return (
      data as {
        clients: VPNClientRecord[];
      }
    ).clients.map(clientListMetadata);
  }

  return [];
}

export function createVPNClient(
  tenantID: string,
  name: string,
  expiresAt?: string
) {
  return cpFetch<VPNClientRecord>(
    `/api/v1/tenants/${tenantID}/vpn-clients`,
    {
      method: "POST",
      body: {
        name,
        ...(expiresAt
          ? {
              expires_at:
                expiresAt,
            }
          : {}),
      },
    }
  );
}

export async function getVPNServices(
  nodeID: string
): Promise<VPNServiceRecord[]> {
  const data =
    await cpFetch<unknown>(
      `/api/v1/nodes/${nodeID}/vpn-services`
    );

  if (Array.isArray(data)) {
    return data as VPNServiceRecord[];
  }

  if (
    data &&
    typeof data === "object" &&
    Array.isArray(
      (
        data as {
          services?: unknown;
        }
      ).services
    )
  ) {
    return (
      data as {
        services: VPNServiceRecord[];
      }
    ).services;
  }

  return [];
}

export function getVPNService(id: string) {
  return cpFetch<VPNServiceRecord>(`/api/v1/vpn-services/${encodeURIComponent(id)}`);
}


export type VPNServiceRealityRecord = {
  service_id: string;
  tenant_id: string;
  destination: string;
  server_name: string;
  fingerprint: string;
  short_id: string;
  secret_ref: string;
};

export type VPNServiceMutationResult = {
  service_id: string;
  generation: number;
  status: string;
};

export type CreateVPNServiceInput = {
  name: string;
  protocol: string;
  listen: string;
  port: number;
  transport: string;
  security: string;
  public_address?: string;
  public_port?: number;
};

export function createVPNService(
  nodeID: string,
  input: CreateVPNServiceInput
) {
  return cpFetch<VPNServiceRecord>(
    `/api/v1/nodes/${nodeID}/vpn-services`,
    {
      method: "POST",
      body: input,
    }
  );
}

export function getVPNServiceReality(
  serviceID: string
) {
  return cpFetch<VPNServiceRealityRecord>(
    `/api/v1/vpn-services/${serviceID}/reality`
  );
}

export function configureVPNServiceReality(
  serviceID: string,
  input: {
    destination: string;
    server_name: string;
    fingerprint: string;
  }
) {
  return cpFetch<VPNServiceRealityRecord>(
    `/api/v1/vpn-services/${serviceID}/reality`,
    {
      method: "POST",
      body: input,
    }
  );
}

export function updateVPNServiceReality(
  serviceID: string,
  input: {
    destination: string;
    server_name: string;
    fingerprint: string;
  }
) {
  return cpFetch<VPNServiceMutationResult>(
    `/api/v1/vpn-services/${serviceID}/reality`,
    {
      method: "PATCH",
      body: input,
    }
  );
}

export function enableVPNService(
  serviceID: string
) {
  return cpFetch<VPNServiceMutationResult>(
    `/api/v1/vpn-services/${serviceID}/enable`,
    {
      method: "POST",
      body: {},
    }
  );
}

export function disableVPNService(
  serviceID: string
) {
  return cpFetch<VPNServiceMutationResult>(
    `/api/v1/vpn-services/${serviceID}/disable`,
    {
      method: "POST",
      body: {},
    }
  );
}

export function deleteVPNService(serviceID: string, confirmName: string) {
  return cpFetch<{
    service_id: string;
    node_id: string;
    deleted: boolean;
    generation: number;
    affected_clients: number;
    affected_plans: number;
  }>(`/api/v1/vpn-services/${encodeURIComponent(serviceID)}`, {
    method: "DELETE",
    body: { confirm_name: confirmName },
    timeoutMs: 35_000,
  });
}

export function provisionVPNClient(
  serviceID: string,
  clientID: string
) {
  return cpFetch<{
    service_id: string;
    client_id: string;
    generation: number;
    status: string;
  }>(
    `/api/v1/vpn-services/${serviceID}/clients/${clientID}/provision`,
    {
      method: "POST",
      body: {},
    }
  );
}


export async function getVPNClientDirectServiceIDs(
  clientID: string
): Promise<string[]> {
  const data =
    await cpFetch<{
      service_ids?: string[];
    }>(
      `/api/v1/vpn-clients/${clientID}/services`
    );

  return data.service_ids ?? [];
}

export function detachVPNClientService(
  serviceID: string,
  clientID: string
) {
  return cpFetch<void>(
    `/api/v1/vpn-services/${serviceID}/clients/${clientID}`,
    {
      method: "DELETE",
    }
  );
}

export async function getVPNClientConnections(
  clientID: string
): Promise<VPNClientConnection[]> {
  const data =
    await cpFetch<{
      connections?: VPNClientConnection[];
    }>(
      `/api/v1/vpn-clients/${clientID}/connections`,
      { timeoutMs: 30_000 }
    );

  return data.connections ?? [];
}

export type VPNClientSubscription = {
  id: string;
  client_id: string;
  status: string;
  token_version: number;
  token_prefix: string;
  created_at: string;
  rotated_at?: string | null;
  last_access_at?: string | null;
  path: string;
};

export function createVPNClientSubscription(
  clientID: string
) {
  return cpFetch<VPNClientSubscription>(
    `/api/v1/vpn-clients/${clientID}/subscription`,
    {
      method: "POST",
    }
  );
}

export function getVPNClientSubscription(
  clientID: string
) {
  return cpFetch<VPNClientSubscription>(
    `/api/v1/vpn-clients/${clientID}/subscription`
  );
}

export function rotateVPNClientSubscription(
  clientID: string
) {
  return cpFetch<VPNClientSubscription>(
    `/api/v1/vpn-clients/${clientID}/subscription/rotate`,
    {
      method: "POST",
    }
  );
}

export async function getTenantBranding(tenant: string) { return cpFetch<import("@/lib/branding-values").TenantBranding>(`/api/v1/tenants/${tenant}/branding`); }
export async function getAutoProfile(tenant: string) { return cpFetch<import("@/lib/auto-profile-values").AutoProfileSettings>(`/api/v1/tenants/${tenant}/auto-profile`); }
export async function saveAutoProfile(tenant: string, value: Omit<import("@/lib/auto-profile-values").AutoProfileSettings, "tenant_id">) { return cpFetch<import("@/lib/auto-profile-values").AutoProfileSettings>(`/api/v1/tenants/${tenant}/auto-profile`, { method: "PUT", body: value }); }
export async function saveTenantBranding(tenant: string, value: Omit<import("@/lib/branding-values").TenantBranding, "tenant_id">) { return cpFetch<import("@/lib/branding-values").TenantBranding>(`/api/v1/tenants/${tenant}/branding`, { method: "PUT", body: value }); }

export async function getMonitoringStatus() { return cpFetch<import("@/lib/monitoring-values").MonitoringStatus>("/api/v1/operations/incidents"); }
export async function acknowledgeIncident(id: string) { return cpFetch<import("@/lib/monitoring-values").MonitoringIncident>(`/api/v1/operations/incidents/${id}/acknowledge`, { method: "POST", body: {} }); }

export async function getWebhookEndpoints(tenant: string) { return (await cpFetch<{ endpoints: import("@/lib/webhook-values").WebhookEndpoint[] }>(`/api/v1/tenants/${tenant}/webhooks`)).endpoints; }
export async function getWebhookDeliveries(tenant: string) { return (await cpFetch<{ deliveries: import("@/lib/webhook-values").WebhookDelivery[] }>(`/api/v1/tenants/${tenant}/webhook-deliveries`)).deliveries; }
export async function getWebhookStatus() { return cpFetch<{ configured: boolean; queue: import("@/lib/monitoring-values").WebhookQueueStatus }>("/api/v1/webhooks/status"); }
export async function createWebhookEndpoint(tenant: string, body: { name: string; url: string; events: string[] }) { return cpFetch<{ endpoint: import("@/lib/webhook-values").WebhookEndpoint; signing_secret: string }>(`/api/v1/tenants/${tenant}/webhooks`, { method: "POST", body }); }
export async function setWebhookEnabled(id: string, enabled: boolean) { return cpFetch<import("@/lib/webhook-values").WebhookEndpoint>(`/api/v1/webhooks/${id}`, { method: "PATCH", body: { enabled } }); }
export async function retryWebhookDelivery(id: string) { return cpFetch<unknown>(`/api/v1/webhook-deliveries/${id}/retry`, { method: "POST", body: {} }); }
export async function deleteWebhookEndpoint(id: string) { return cpFetch<unknown>(`/api/v1/webhooks/${id}`, { method: "DELETE" }); }

export async function getAuditHistory(query: string) { return cpFetch<import("@/lib/audit-values").AuditHistory>(`/api/v1/audit-events?${query}`); }
export async function getAuditEventTypes() { return (await cpFetch<{ types: string[] }>("/api/v1/audit-event-types")).types; }

export async function createPartnerOwner(name: string) { return cpFetch<{ id: string; name: string }>("/api/v1/tenants", { method: "POST", body: { name } }); }
export async function getPartnerChildren(tenant: string) { return (await cpFetch<{ children: import("@/lib/reseller-values").ResellerChild[] }>(`/api/v1/tenants/${tenant}/children`)).children; }

export async function getTenantLimits(tenant: string) { return cpFetch<import("@/lib/tenant-limit-values").TenantLimits>(`/api/v1/tenants/${tenant}/limits`); }
export async function saveTenantLimits(tenant: string, max_clients: number, max_plans: number) { return cpFetch<import("@/lib/tenant-limit-values").TenantLimits>(`/api/v1/tenants/${tenant}/limits`, { method: "PUT", body: { max_clients, max_plans } }); }

export function getOwnMFAStatus() { return cpFetch<import("@/lib/admin-mfa-types").AdminMFAStatus>("/api/v1/admin/me/mfa"); }
export function changeOwnMFA<T>(operation: string, body: { password: string; code: string; recovery_code: string }) { return cpFetch<T>(`/api/v1/admin/me/mfa/${operation}`, { method: "POST", body }); }

export function saveVPNSubscriptionName(id: string, name: string) {
  return cpFetch<VPNServiceRecord>(`/api/v1/vpn-services/${encodeURIComponent(id)}/subscription-name`, { method: "PUT", body: { name } });
}
export function updateVPNServiceSettings(
  id: string,
  input: { name: string; listen: string; port: number; transport: string; public_address: string; public_port: number }
) {
  return cpFetch<{ service: VPNServiceRecord; generation: number; status: "accepted" }>(`/api/v1/vpn-services/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: input,
  });
}


export type AmneziaWGConfiguration = { service_id: string; version: string; updated_at: string };
export function getAmneziaWG(id: string) { return cpFetch<AmneziaWGConfiguration>(`/api/v1/vpn-services/${encodeURIComponent(id)}/amneziawg`); }
export function configureAmneziaWG(id: string, version: string) { return cpFetch<{amneziawg: AmneziaWGConfiguration; generation: number}>(`/api/v1/vpn-services/${encodeURIComponent(id)}/amneziawg`, {method:"PUT",body:{version}}); }
export function importReviewedAmneziaWG() { return cpFetch<{created: boolean; release: CoreRelease}>("/api/v1/core-releases/amneziawg/import-reviewed",{method:"POST"}); }
export function approveReviewedAmneziaWG() { return cpFetch<{approved: boolean}>("/api/v1/core-releases/amneziawg/approve-reviewed",{method:"POST"}); }
export function initializeAmneziaWG(id: string) { return cpFetch<{generation: number; changed: boolean}>(`/api/v1/nodes/${encodeURIComponent(id)}/initialize-amneziawg`,{method:"POST"}); }
