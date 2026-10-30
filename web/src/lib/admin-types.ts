export type AdminRole = "owner" | "admin" | "monitor";
export type AdminAccount = {
  id: string; username: string; role: AdminRole; enabled: boolean;
  security_version: number; created_at: string; updated_at: string; last_login_at: string | null;
};
export type AdminSession = { id: string; account: AdminAccount; created_at: string; expires_at: string };
export type AdminSessionInfo = { id: string; created_at: string; expires_at: string; current: boolean };
export const adminRoleLabels: Record<AdminRole, string> = { owner: "Владелец", admin: "Администратор", monitor: "Наблюдатель" };
