export type NodeSecurityPolicy={mode:"audit"|"protect";update_hold:boolean;revision:number};
export type NodeSecurityReport={policy_revision:number;agent_version:string;kernel:string;mptcp_disabled:boolean|null;tcp_migrate_disabled:boolean|null;ipv4_options_filter:boolean|null;mptcp_listeners:number|null;inodes_used_percent:number|null;nofile_soft:number|null;public_management_listeners:number|null;apply_result:string};
export type NodeSecurityStatus={node_id:string;policy:NodeSecurityPolicy;report:NodeSecurityReport|null;received_at:string|null;fresh:boolean;mitigation_ready:boolean};
export type NodeReadiness={diagnostics:{overall:string;checks:{code:string;status:string;message:string}[]};services:{id:string;name:string;protocol:string;enabled:boolean;active_assignments:number;certificate:string;ingress_mode:string;ingress_ready:boolean}[]};

// A cached successful response must age out even when further requests fail.
export function nodeSecurityReportFreshAt(data: NodeSecurityStatus, now: number): boolean {
  if (!data.report || !data.fresh || !data.received_at || !Number.isFinite(now)) return false;
  const age = now - Date.parse(data.received_at);
  return Number.isFinite(age) && age >= 0 && age < 150_000;
}
