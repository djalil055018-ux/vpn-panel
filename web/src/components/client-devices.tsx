"use client";

import { useEffect, useState, useTransition } from "react";
import { readClientDevices, saveClientDeviceLimit, removeClientDevice } from "@/app/client-device-actions";
import type { DeviceActionResult, RegisteredDevices } from "@/lib/client-devices";
import { NavIcon } from "@/components/ui/nav-icon";

function date(value: string) {
  return new Date(value).toLocaleString("ru-RU", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "Europe/Moscow" });
}

export function ClientDevices({ clientID }: { clientID: string }) {
  const [data, setData] = useState<RegisteredDevices | null>(null);
  const [feedback, setFeedback] = useState({ ok: true, message: "" });
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState("0");
  const [confirmID, setConfirmID] = useState<string | null>(null);
  const [pending, start] = useTransition();
  useEffect(() => {
    let active = true;
    readClientDevices(clientID).then(result => {
      if (!active) return;
      if (result.data) { setData(result.data); setLimit(String(result.data.limit)); }
      setFeedback({ ok: result.ok, message: result.message }); setLoading(false);
    }).catch(() => {
      if (active) { setFeedback({ ok: false, message: "Не удалось загрузить устройства." }); setLoading(false); }
    });
    return () => { active = false; };
  }, [clientID]);

  function accept(result: DeviceActionResult) {
    if (result.data) { setData(result.data); setLimit(String(result.data.limit)); }
    setFeedback({ ok: result.ok, message: result.message });
    if (result.ok) setConfirmID(null);
  }
  function refresh() {
    start(async () => {
      try { accept(await readClientDevices(clientID)); }
      catch { setFeedback({ ok: false, message: "Не удалось обновить список устройств." }); }
    });
  }
  return <div className="client-devices" aria-busy={pending || loading}>
    <div className="client-devices-summary">
      <span className="client-metric-icon"><NavIcon name="nodes" /></span>
      <div><strong>{data ? `${data.count} ${data.limit ? `из ${data.limit}` : "· без лимита"}` : "Устройства подписки"}</strong><span>Привязанные устройства</span></div>
      <button type="button" className="button ghost" onClick={refresh} disabled={pending || loading} aria-label="Обновить устройства">↻</button>
    </div>
    {loading && <p className="plan-muted" role="status">Загружаю привязки…</p>}
    {data && <>
      <form className="client-device-limit" onSubmit={event => {
        event.preventDefault(); const form = new FormData(event.currentTarget);
        start(async () => {
          try { accept(await saveClientDeviceLimit(form)); }
          catch { setFeedback({ ok: false, message: "Не удалось сохранить лимит." }); }
        });
      }}>
        <input type="hidden" name="client_id" value={clientID} />
        <label>Максимум устройств<input aria-describedby={`device-limit-note-${clientID}`} name="limit" type="number" min={0} max={1000} step={1} required value={limit} onChange={event => setLimit(event.target.value)} disabled={pending} /></label>
        <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : "Сохранить лимит"}</button>
        <small id={`device-limit-note-${clientID}`}>0 — без ограничений. Место освобождается после удаления привязки, а не после отключения VPN.</small>
      </form>
      <div className="client-device-help"><NavIcon name="shield" width={16} height={16} /><p>Лимит проверяется при добавлении и обновлении подписки в приложении с поддержкой HWID, например Happ или v2RayTun. Приложение без идентификатора не получит подписку, если лимит включён.</p></div>
      {data.devices.length ? <ul className="client-device-list">{data.devices.map(device => <li key={device.id}>
        <div className="client-device-identity"><span className="client-device-platform">{device.platform || "Устройство"}</span><strong>{device.model || "Модель не указана"}</strong><small>{[device.os_version, device.identifier_hint].filter(Boolean).join(" · ")}</small></div>
        <div className="client-device-dates"><span>Добавлено <time dateTime={device.created_at}>{date(device.created_at)}</time></span><span>Подписка обновлена <time dateTime={device.last_seen_at}>{date(device.last_seen_at)}</time></span></div>
        {confirmID === device.id ? <div className="client-device-confirm"><span>Удалить привязку?</span><button type="button" className="button danger" disabled={pending} onClick={() => {
          const form = new FormData(); form.set("client_id", clientID); form.set("device_id", device.id);
          start(async () => {
            try { accept(await removeClientDevice(form)); }
            catch { setFeedback({ ok: false, message: "Не удалось удалить привязку." }); }
          });
        }}>Удалить</button><button type="button" className="button ghost" disabled={pending} onClick={() => setConfirmID(null)}>Отмена</button></div>
          : <button type="button" className="button ghost" disabled={pending} onClick={() => setConfirmID(device.id)} aria-label={`Удалить привязку: ${device.model || device.platform || device.identifier_hint}`}>Удалить</button>}
      </li>)}</ul> : <div className="client-devices-empty"><strong>Устройства пока не привязаны</strong><p>Они появятся после загрузки подписки в приложении, передающем идентификатор устройства.</p></div>}
      <p className="client-device-footnote">Удаление привязки освобождает место, но не отключает ранее загруженный VPN-профиль. При свободном месте устройство может добавить подписку снова.</p>
    </>}
    {feedback.message && <p role="status" className={feedback.ok ? "plan-feedback" : "plan-feedback error"}>{feedback.message}</p>}
    {!data && !loading && <button type="button" className="button ghost" disabled={pending} onClick={refresh}>Повторить загрузку</button>}
  </div>;
}
