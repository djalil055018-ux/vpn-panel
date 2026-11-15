import type {IngressEntry} from "./ingress-types";
export type IngressPolicy={mode:string;revision:number};
export type ProtocolIngressService={id:string;name:string;protocol:string;transport:string;security:string;enabled:boolean;policy:IngressPolicy;effective_mode:string;supported:boolean;reason:string;port:number;ready:boolean};
export type NodeProtocolIngress={node_id:string;policy:IngressPolicy;entries:IngressEntry[];services:ProtocolIngressService[]};
