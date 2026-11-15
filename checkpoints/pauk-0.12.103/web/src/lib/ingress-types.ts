export type IngressProbe={host:string;port:number;ok:boolean;error?:string;latency_ms:number;certificate_expires_at?:string};
export type IngressEntry={id:string;name:string;address:string;https_port:number;panel_port:number;kind:"native"|"bridge";ready:boolean;checked_at?:string;check_status:string;check_details:IngressProbe[]};
export type IngressConfig={revision:number;vpn_enabled:boolean;web_enabled:boolean;primary_id:string;secondary_id:string;probe_interval_seconds:number;panel_host:string;subscription_host:string;legacy_hosts:string[];entries:IngressEntry[]};
export type IngressSettings=Pick<IngressConfig,"revision"|"vpn_enabled"|"web_enabled"|"primary_id"|"secondary_id"|"probe_interval_seconds">;
export type IngressDNS={all_match:boolean;records:{host:string;expected:string[];observed:string[];ok:boolean}[];checked_at:string;source:string;edits_applied:false};
export type IngressCandidate={node_id:string;name:string;addresses:string[];available:boolean;reason:string};
export type IngressProvisionRun={id:string;node_id:string;name:string;address:string;status:"running"|"completed"|"failed";phase:string;failure_code:string;created_at:string};
export type IngressProvisionOverview={candidates:IngressCandidate[];runs:IngressProvisionRun[]};
