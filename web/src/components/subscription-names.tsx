"use client";

import { useState, useTransition } from "react";
import { saveSubscriptionName } from "@/app/subscription-name-actions";
import type { VPNServiceRecord } from "@/lib/control-plane";
import { NavIcon } from "@/components/ui/nav-icon";

const countries = [
  ["NL", "Нидерланды"], ["RU", "Россия"], ["SE", "Швеция"], ["DE", "Германия"],
  ["FI", "Финляндия"], ["PL", "Польша"], ["FR", "Франция"], ["GB", "Великобритания"],
  ["US", "США"], ["CA", "Канада"], ["CH", "Швейцария"], ["AT", "Австрия"],
  ["EE", "Эстония"], ["LV", "Латвия"], ["LT", "Литва"], ["NO", "Норвегия"],
  ["DK", "Дания"], ["CZ", "Чехия"], ["ES", "Испания"], ["IT", "Италия"],
  ["TR", "Турция"], ["KZ", "Казахстан"], ["GE", "Грузия"], ["AM", "Армения"],
  ["AE", "ОАЭ"], ["JP", "Япония"], ["SG", "Сингапур"], ["AU", "Австралия"],
];
const flag = (code: string) => [...code].map(c => String.fromCodePoint(127397 + c.charCodeAt(0))).join("");
const splitName = (name: string) => { const match = name.match(/^\p{Regional_Indicator}{2}\s*/u); return { flag: match?.[0].trim() ?? "", text: match ? name.slice(match[0].length) : name }; };

function NameEditor({ node, service }: { node: string; service: VPNServiceRecord }) {
  const fallback = service.subscription_default_name ?? service.name;
  const initial = service.subscription_name ?? fallback;
  const [name, setName] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const [custom, setCustom] = useState(Boolean(service.subscription_name));
  const [feedback, setFeedback] = useState({ ok: true, message: "" });
  const [pending, start] = useTransition();
  const parts = splitName(name.trim());
  const knownFlag = countries.some(([code]) => flag(code) === parts.flag);
  const transport = service.protocol === "hysteria2" ? "UDP" : service.transport.toUpperCase();
  const description = `${service.protocol === "hysteria2" ? "Hysteria 2" : service.protocol.toUpperCase()} · ${transport} · ${service.security.toUpperCase()}`;
  const fieldID = `subscription-name-${service.id}`;

  function save(reset = false) {
    const data = new FormData(); data.set("node_id", node); data.set("service_id", service.id);
    data.set("name", name); data.set("operation", reset ? "reset" : "save");
    start(async () => {
      try {
        const result = await saveSubscriptionName(data);
        setFeedback(result);
        if (result.ok && result.name !== undefined) { setName(result.name); setSaved(result.name); setCustom(Boolean(result.custom)); }
      } catch { setFeedback({ ok: false, message: "Связь прервалась. Попробуйте сохранить ещё раз." }); }
    });
  }

  return <article className="subscription-name-card" aria-label={`Название профиля: ${service.name}`} aria-busy={pending}>
    <div className="subscription-name-preview" aria-label="Предпросмотр названия">
      <span className="subscription-name-flag" aria-hidden="true">{parts.flag || <NavIcon name="nodes" width={23} height={23} />}</span>
      <div><strong>{parts.text || "Название профиля"}</strong><small>{description}</small></div>
      <span className={`subscription-name-state ${service.enabled ? "enabled" : ""}`}>{service.enabled ? "Включён" : "Отключён"}</span>
    </div>
    <form className="subscription-name-form" onSubmit={event => { event.preventDefault(); save(); }}>
      <label htmlFor={`${fieldID}-flag`}>Флаг<select id={`${fieldID}-flag`} value={parts.flag} disabled={pending} onChange={event => { setName([event.target.value, splitName(name.trim()).text].filter(Boolean).join(" ")); setFeedback({ ok: true, message: "" }); }}>
        <option value="">Без флага</option>
        {!knownFlag && parts.flag && <option value={parts.flag}>{parts.flag} · свой флаг</option>}
        {countries.map(([code, title]) => <option key={code} value={flag(code)}>{flag(code)} {title}</option>)}
      </select></label>
      <label htmlFor={fieldID}>Название в приложении<input id={fieldID} value={name} disabled={pending} required maxLength={400} aria-describedby={`${fieldID}-note`} onChange={event => { setName(event.target.value); setFeedback({ ok: true, message: "" }); }} placeholder="🇳🇱 Нидерланды · XHTTP" /></label>
      <button className="button primary" disabled={pending || !name.trim() || name.trim() === saved}>{pending ? "Сохранение…" : "Сохранить"}</button>
    </form>
    <div className="subscription-name-note" id={`${fieldID}-note`}><span>Профиль: {service.name} · порт {service.public_port ?? service.port}</span>
      <button type="button" className="subscription-name-reset" disabled={pending || (!custom && name === saved)} onClick={() => { if (custom) save(true); else { setName(saved); setFeedback({ ok: true, message: "" }); } }}>{custom ? "Вернуть исходное название" : "Отменить изменения"}</button>
    </div>
    {feedback.message && <p role="status" className={`subscription-name-feedback ${feedback.ok ? "success" : "error"}`}>{feedback.message}</p>}
  </article>;
}

export function SubscriptionNames({ node, services }: { node: string; services: VPNServiceRecord[] }) {
  if (!services.length) return null;
  return <section className="panel subscription-names" id="subscription-names" aria-labelledby="subscription-names-heading">
    <div className="subscription-names-heading"><span className="subscription-names-icon"><NavIcon name="settings" width={22} height={22}/></span><div><h2 id="subscription-names-heading">Названия в подписке</h2><p>Выберите флаг и название, которое клиенты увидят в VPN-приложении.</p></div><span className="subscription-names-count">{services.length}</span></div>
    <p className="subscription-names-help">Текст передаётся как указан, без добавления «PAUK». Можно вставить свой флаг или эмодзи. После сохранения обновите подписку в приложении.</p>
    <div className="subscription-names-list">{services.map(service => <NameEditor key={service.id} node={node} service={service}/>)}</div>
  </section>;
}
