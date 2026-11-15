"use client";

import { useActionState } from "react";
import { activateRemnawaveAction } from "@/app/remnawave-activation-actions";

type Plan = { id: string; name: string };

export function RemnawaveActivationForm({ migration, digest, plans }: { migration: string; digest: string; plans: Plan[] }) {
  const [state, action, pending] = useActionState(activateRemnawaveAction, { status: "", message: "" });
  return (
    <form action={action} className="portal-form branding-form">
      <input type="hidden" name="migration" value={migration} />
      <input type="hidden" name="digest" value={digest} />
      <label>Группа доступа для всех клиентов
        <select name="plan" required defaultValue="" disabled={pending || plans.length === 0}>
          <option value="" disabled>Выберите группу</option>
          {plans.map((plan) => <option key={plan.id} value={plan.id}>{plan.name}</option>)}
        </select>
      </label>
      <label>Часовой пояс исходного расписания
        <input name="timezone" required maxLength={64} defaultValue="UTC" disabled={pending} aria-describedby="remnawave-timezone-help" />
      </label>
      <p className="plan-muted" id="remnawave-timezone-help">
        В стандартной установке Remnawave используется UTC. Если на исходном сервере задан другой пояс, укажите его, например Europe/Moscow.
      </p>
      <label className="plan-check">
        <input name="confirm" value="yes" type="checkbox" required disabled={pending} />
        Я сверил снимок и выдам клиентам ссылки PAUK. Старые ссылки остаются в исходной панели.
      </label>
      <button className="button primary" disabled={pending || plans.length === 0}>
        {pending ? "Перенос…" : "Перенести клиентов в PAUK"}
      </button>
      {state.message && <p role="status" className={state.status === "ok" ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}
    </form>
  );
}
