"use client";
import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { adminBrandingAction, portalBrandingAction } from "@/app/branding-actions";
import { brandAccents, type TenantBranding } from "@/lib/branding-values";
function Submit() { const { pending } = useFormStatus();return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : "Сохранить оформление"}</button>; }
export function BrandingForm({ branding, portal = false }: { branding: TenantBranding; portal?: boolean }) {
  const [state, action] = useActionState(portal ? portalBrandingAction : adminBrandingAction, { ok: false, message: "" });
  return <form action={action} className="portal-form branding-form"><input name="tenant_id" type="hidden" value={branding.tenant_id} /><label>Название бренда<input name="display_name" required maxLength={80} defaultValue={branding.display_name} /></label><label>Описание кабинета<input name="tagline" maxLength={160} defaultValue={branding.tagline} placeholder="Управляйте своим доступом к VPN" /></label><label>Цвет оформления<select name="accent" defaultValue={branding.accent}>{brandAccents.map(accent => <option key={accent.value} value={accent.value}>{accent.label}</option>)}</select></label><label>Подпись ссылки поддержки<input name="support_label" maxLength={40} defaultValue={branding.support_label} placeholder="Написать в поддержку" /></label><label>Ссылка поддержки<input name="support_url" type="url" maxLength={500} defaultValue={branding.support_url} placeholder="https://…" /></label><p className="plan-muted">Для поддержки заполните и подпись, и HTTPS-ссылку. Пустые поля скрывают ссылку. Оформление применяется после входа; страница входа остаётся общей.</p><Submit />{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}</form>;
}
