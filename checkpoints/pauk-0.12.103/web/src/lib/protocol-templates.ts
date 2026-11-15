export type TemplateFile = { name: string; role: string; language: string; content: string; sha256: string };
export type TemplateSource = { id: string; repository: string; ref: string; path: string; url: string; blob_sha: string; sha256: string };
export type ProtocolTemplate = {
  id: string; name: string; family: string; protocol: string; transport: string; security: string; runtime: string;
  recommended: boolean; legacy: boolean; summary: string; latency_note: string; traffic_quota_bytes: number;
  speed_limit_mbps: number; placeholders: string[]; files: TemplateFile[]; sources: string[]; notes: string[];
  selection_mode: string; default_port: number;
};
export type ProtocolTemplateCatalog = { schema: string; version: string; reviewed_at: string; notice: string; sources: TemplateSource[]; templates: ProtocolTemplate[] };
export type TemplateChoice = { id: string; name: string };
export type TemplateTarget = {
 node_id: string; tenant_id: string; name: string; runtime: string; agent: string; core_version: string;
 desired_generation: number; applied_generation: number; healthy: boolean; registered: boolean;
 agent_ready: boolean; imported: boolean; status: string; enabled_services: number;
 public_address: string; reality_target: string; server_name: string; suggested_port: number;
 certificates: TemplateChoice[]; plans: TemplateChoice[]; ready: boolean; reasons: string[];
};
export type TemplateApplicationInput = {
 node_id: string; name: string; public_address: string; port: number; certificate_id: string;
 reality_target: string; server_name: string; plan_ids: string[]; request_key: string;
 expected_generation: number; revision: string;
};
export type TemplatePreview = { template_id: string; revision: string; target: TemplateTarget; ready: boolean; reasons: string[]; input: TemplateApplicationInput };
export type TemplateApplication = { request_key: string; template_id: string; node_id: string; service_id: string; generation: number; status: string; replayed: boolean };
export type TemplateTargets = { targets: TemplateTarget[]; minimum_agent: string; revision: string };
