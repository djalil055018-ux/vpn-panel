"use client";
import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { tenantLimitAction } from "@/app/tenant-limit-actions";
import type { TenantLimits } from "@/lib/tenant-limit-values";
function Submit() { const { pending } = useFormStatus();return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : "Сохранить лимиты"}</button>; }
export function TenantLimitForm({ limits }: { limits: TenantLimits }) { const [state, action] = useActionState(tenantLimitAction, { ok: false, message: "" });return <form action={action} className="plan-form"><input type="hidden" name="tenant_id" value={limits.tenant_id} /><label>Максимум клиентов<input name="max_clients" type="number" min={0} max={100000} required defaultValue={limits.max_clients} /></label><label>Максимум тарифов<input name="max_plans" type="number" min={0} max={10000} required defaultValue={limits.max_plans} /></label><p className="plan-muted">Ноль — без ограничения. Учитываются все записи, включая отключённые и просроченные. Лимит не может быть ниже текущего количества.</p><Submit />{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}</form>; }
