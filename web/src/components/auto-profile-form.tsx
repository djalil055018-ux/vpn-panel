"use client";
import "@/app/auto-profile.css";
import { useActionState, useState } from "react";
import { useFormStatus } from "react-dom";
import { adminAutoProfileAction, portalAutoProfileAction } from "@/app/auto-profile-actions";
import type { AutoProfileSettings } from "@/lib/auto-profile-values";
import { NavIcon } from "@/components/ui/nav-icon";

function Submit() {
  const { pending } = useFormStatus();
  return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : "Сохранить настройки"}</button>;
}
export function AutoProfileForm({ settings, portal = false }: { settings: AutoProfileSettings; portal?: boolean }) {
  const [state, action, pending] = useActionState(portal ? portalAutoProfileAction : adminAutoProfileAction, { ok: false, message: "" });
  const [name, setName] = useState(settings.name);
  const [enabled, setEnabled] = useState(settings.enabled);
  const [direct, setDirect] = useState(settings.russia_direct);
  return <div className="auto-profile-layout">
    <form action={action} onReset={event => event.preventDefault()} aria-busy={pending} className="auto-profile-form">
      <input name="tenant_id" type="hidden" value={settings.tenant_id} />
      <div className="auto-profile-title"><span className="subscription-names-icon"><NavIcon name="cascade" width={24} height={24} /></span><div><h2>Одно название. Все серверы.</h2><p>Панель распределяет клиентов между доступными узлами.</p></div></div>
      <label className="auto-profile-toggle"><span><strong>Добавить автоматический профиль</strong><small>Появится первым после обновления подписки</small></span><input type="checkbox" name="enabled" checked={enabled} disabled={pending} onChange={e => setEnabled(e.target.checked)} /></label>
      <label className="auto-profile-name">Название в приложении<input name="name" value={name} disabled={pending} onChange={e => setName(e.target.value)} required maxLength={160} placeholder="Авто" aria-describedby="auto-name-help" /><small id="auto-name-help">До 80 символов. Можно добавить флаг или другой эмодзи.</small></label>
      <label className="auto-profile-toggle"><span><strong>Российские сайты напрямую</strong><small>Остальной трафик — через VPN</small></span><input type="checkbox" name="russia_direct" checked={direct} disabled={pending} onChange={e => setDirect(e.target.checked)} /></label>
      <div className="auto-profile-submit"><Submit />{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}</div>
    </form>
    <aside className="auto-profile-preview" aria-label="Предпросмотр профиля">
      <p className="eyebrow">В ПРИЛОЖЕНИИ КЛИЕНТА</p>
      <div className={`auto-profile-sample${enabled ? " enabled" : ""}`}><span className="auto-profile-symbol">↗</span><div><strong>{name.trim() || "Авто"}</strong><small>{enabled ? "Автоматический выбор сервера" : "Профиль выключен"}</small></div><span className="auto-profile-badge">АВТО</span></div>
      <div className="auto-profile-path"><span>Устройство клиента</span><i aria-hidden="true">↓</i><div><span>Российские сайты<strong>{direct ? "Напрямую" : "Через VPN"}</strong></span><span>Остальные сайты<strong>Через VPN</strong></span></div></div>
      <p className="auto-profile-caption">Ручной выбор страны и протокола остаётся в подписке.</p>
    </aside>
  </div>;
}
export function AutoProfileHelp() {
  return <section className="panel auto-profile-help"><h2>Как это работает</h2><div>
    <article><span>01</span><h3>Все доступные серверы</h3><p>В выборе участвуют исправные серверы, уже доступные клиенту по его группам и тарифу. Несколько протоколов на одном узле не увеличивают его долю клиентов.</p></article>
    <article><span>02</span><h3>Устойчивое назначение</h3><p>Сервер сохраняется при обновлении подписки. Если он недоступен, новое назначение появится после следующего обновления. Действующие соединения не переносятся.</p></article>
    <article><span>03</span><h3>Маршруты внутри приложения</h3><p>Полный Xray-конфиг включает прямой доступ к РФ только для «Авто». В конфигурациях sing-box и Mihomo правила действуют на весь импорт. Приложения, принимающие лишь ссылки, требуют собственной настройки маршрутов.</p></article>
  </div><p className="plan-muted">Страна сайта определяется по спискам доменов и IP: у отдельных сайтов и CDN возможны исключения. Недоступность VPN не переводит зарубежный трафик на прямое соединение.</p></section>;
}
