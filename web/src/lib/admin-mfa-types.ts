export type AdminMFAStatus = {
  configured: boolean;
  status: { enabled: boolean; pending_expires_at: string | null; recovery_codes_remaining: number };
};
export type MFAActionState = {
  ok: boolean;
  message: string;
  enrollment?: { secret: string; provisioning_url: string; expires_at: string };
  recovery_codes?: string[];
  completed?: boolean;
};
