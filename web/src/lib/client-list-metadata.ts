export type ClientDirectoryMetadata = {
  numeric_id?: number;
  telegram_id?: string | null;
  tag?: string | null;
  groups: string[];
  last_node_name?: string | null;
  first_connected_at?: string | null;
  last_online_at?: string | null;
  last_traffic_reset_at?: string | null;
  lifetime_used_bytes?: number | null;
  connection_state?: "online" | "offline" | "never" | "unknown";
  source_status?: string;
  source_observed_at?: string;
};

export type ClientListRecord = {
  id: string;
  tenant_id: string;
  name: string;
  status: string;
  effective_status: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
  remnawave_hold?: boolean;
  directory?: ClientDirectoryMetadata;
};

// Never spread a Control Plane client into a Client Component. API records can
// include credentials, and a TypeScript assertion does not remove those fields.
export function clientListMetadata(client: ClientListRecord): ClientListRecord {
  return {
    id: client.id,
    tenant_id: client.tenant_id,
    name: client.name,
    status: client.status,
    effective_status: client.effective_status,
    expires_at: client.expires_at,
    created_at: client.created_at,
    updated_at: client.updated_at,
    remnawave_hold: client.remnawave_hold === true,
    directory: client.directory ? {
      numeric_id: client.directory.numeric_id,
      telegram_id: client.directory.telegram_id,
      tag: client.directory.tag,
      groups: [...client.directory.groups],
      last_node_name: client.directory.last_node_name,
      first_connected_at: client.directory.first_connected_at,
      last_online_at: client.directory.last_online_at,
      last_traffic_reset_at: client.directory.last_traffic_reset_at,
      lifetime_used_bytes: client.directory.lifetime_used_bytes,
      connection_state: client.directory.connection_state,
      source_status: client.directory.source_status,
      source_observed_at: client.directory.source_observed_at,
    } : undefined,
  };
}
