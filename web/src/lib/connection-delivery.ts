import type {
  VPNClientConnection,
} from "./control-plane";

export type ConnectionMetadata = {
  service_id: string;
  service_name: string;
  address: string;
  port: number;
  runtime_core?:
    VPNClientConnection["runtime_core"];
  amneziawg_version?: string;
  protocol: string;
  transport: string;
  security: string;
  config_expires_at?: string;
  has_config: boolean;
  has_uri: boolean;
};

export type ConnectionCredential = {
  service_id: string;
  protocol: string;
  kind: "config" | "uri";
  value: string;
  filename?: string;
};

export type ConnectionListActionResult = {
  ok: boolean;
  message: string;
  connections: ConnectionMetadata[];
};

export type ConnectionCredentialActionResult = {
  ok: boolean;
  message: string;
  retryable?: boolean;
  credential?: ConnectionCredential;
};

export type ConnectionArchiveActionResult = {
  ok: boolean;
  message: string;
  retryable?: boolean;
  archive_base64?: string;
  filename?: string;
  mime?: string;
};

export function connectionMetadata(
  connection: VPNClientConnection
): ConnectionMetadata {
  return {
    service_id: connection.service_id,
    service_name: connection.service_name,
    address: connection.address,
    port: connection.port,
    runtime_core: connection.runtime_core,
    amneziawg_version: connection.amneziawg_version,
    protocol: connection.protocol,
    transport: connection.transport,
    security: connection.security,
    config_expires_at:
      connection.config_expires_at,
    has_config:
      Boolean(connection.config),
    has_uri:
      Boolean(connection.uri),
  };
}

export function connectionCredential(
  connection: VPNClientConnection
): ConnectionCredential | undefined {
  if (connection.config) {
    return {
      service_id: connection.service_id,
      protocol: connection.protocol,
      kind: "config",
      value: connection.config,
      filename:
        connection.config_filename,
    };
  }

  if (connection.uri) {
    return {
      service_id: connection.service_id,
      protocol: connection.protocol,
      kind: "uri",
      value: connection.uri,
    };
  }

  return undefined;
}
