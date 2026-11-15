export type AutoRefreshSchedule={enabled:boolean;daily_time:string;timezone:"Europe/Moscow";revision:number;next_run_at:string|null};
export type AutoRefreshPublication={generation:number;refreshed_at:string;available_nodes:number;available_services:number};
export type AutoRefreshRun={id:string;request_key:string;origin:"manual"|"scheduled";status:"published"|"unchanged"|"unavailable"|"disabled";generation:number;available_nodes:number;available_services:number;checked_at:string;replayed:boolean};
export type AutoRefreshStatus={schedule:AutoRefreshSchedule;publication:AutoRefreshPublication|null;runs:AutoRefreshRun[]};
