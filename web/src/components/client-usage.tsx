"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { clientUsageAction } from "@/app/client-usage-actions";
import type { VPNClientUsage } from "@/lib/control-plane";
import { trafficQuota } from "@/lib/usage-policy";

function bytes(value: number) {
  if (value < 1024) return `${value} Б`;
  const units = ["КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ"];
  let amount = value / 1024, unit = units[0];
  for (let index = 1; index < units.length && amount >= 1024; index += 1) { amount /= 1024; unit = units[index]; }
  return `${amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${unit}`;
}
function Submit() { const { pending } = useFormStatus(); return <button className="button ghost" disabled={pending}>{pending ? "Сохранение…" : "Сохранить лимиты"}</button>; }

export function ClientUsage({ clientID, usage }: { clientID: string; usage: VPNClientUsage | null }) {
  const [state, action] = useActionState(clientUsageAction, { ok: false, message: "" });
  if (!usage) return <span className="plan-muted">Данные временно недоступны</span>;
  const quota = trafficQuota(usage);
  if (!quota) return <span className="plan-muted">Политика трафика временно недоступна</span>;
  const percent = quota.limit > 0 ? Math.min(100, usage.used_bytes / quota.limit * 100) : 0;
  return <div className="client-usage">
    <strong className={usage.quota_exceeded ? "operations-warning" : undefined}>{bytes(usage.used_bytes)}{quota.limit > 0 ? ` из ${bytes(quota.limit)}` : " · без лимита"}</strong>
    <span>{quota.continuous ? "Без автоматического сброса" : "За текущий месяц"}</span>
    {quota.continuous && (usage.imported_bytes ?? 0) > 0 && <small>Включая {bytes(usage.imported_bytes!)} из предыдущей панели</small>}
    {quota.limit > 0 && <div className="client-usage-bar" aria-label={`Использовано ${percent.toFixed(0)} процентов`}><span style={{ width: `${percent}%` }} /></div>}
    <span>{usage.active_ips === null ? "Количество активных адресов недоступно" : `${usage.active_ips} активных адресов`}{usage.device_limit > 0 ? ` · порог ${usage.device_limit}` : " · без предупреждения"}</span>
    {usage.device_warning && <small className="operations-warning">Превышен порог активных адресов</small>}
    <details><summary>Настроить</summary><form action={action} className="client-usage-form">
      <input type="hidden" name="client_id" value={clientID} />
      <input type="hidden" name="reset_policy" value={quota.continuous ? "NO_RESET" : "MONTH"} />
      <label>{quota.continuous ? "Общий лимит трафика, ГиБ" : "Трафик в месяц, ГиБ"}<input name={quota.continuous ? "limit_gib" : "monthly_gib"} type="number" min={0} max={9000000000000000 / 1073741824} step="any" required defaultValue={quota.limit / 1073741824} /></label>
      {!quota.continuous && <label>Порог активных адресов<input name="device_limit" type="number" min={0} max={1000} required defaultValue={usage.device_limit} /></label>}
      {quota.continuous && <small>Изменение лимита сохраняет использованный трафик.</small>}
      <small>Ноль снимает лимит. Адреса — ориентир числа подключений; один человек может использовать несколько сетей, а несколько устройств — один общий адрес.</small>
      <Submit />{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}
    </form></details>
  </div>;
}
