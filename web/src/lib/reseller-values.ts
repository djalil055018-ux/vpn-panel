export type ResellerCredential = { id: string; name: string; role: string; expires_at: string; revoked_at: string | null };
export type ResellerChild = { id: string; name: string; created_at: string; client_count: number; service_count: number; credentials?: ResellerCredential[] };
