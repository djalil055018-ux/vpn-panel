"use client";
import { useActionState, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { platformUpdateAction } from "@/app/update-actions";
import type { XrayReleaseChoice } from "@/lib/update-types";

export function UpdateRefresh({ active }: { active: boolean }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => { if (document.visibilityState === "visible") router.refresh(); }, 8000);
    return () => clearInterval(timer);
  }, [active, router]);
  return <button className="button" onClick={() => router.refresh()}>Обновить состояние</button>;
}
export function UpdateButton({ operation, id = "", node = "", requestKey = "", children, disabled = false }: { operation: string; id?: string; node?: string; requestKey?: string; children: React.ReactNode; disabled?: boolean }) {
  const [state, action, pending] = useActionState(platformUpdateAction, { ok: false, message: "" });
  const [key] = useState(requestKey);
  return <form action={action} className="update-action"><input type="hidden" name="operation" value={operation}/><input type="hidden" name="id" value={id}/><input type="hidden" name="node_id" value={node}/><input type="hidden" name="request_key" value={key}/><button className="button primary" disabled={pending || disabled}>{pending ? "Выполнение…" : children}</button>{state.message && <p role="status" className={`plan-feedback ${state.ok ? "" : "error"}`}>{state.message}</p>}</form>;
}
export function XrayApproval({ release }: { release: XrayReleaseChoice }) {
  const [state, action, pending] = useActionState(platformUpdateAction, { ok: false, message: "" });
  return <form action={action} className="update-action"><input type="hidden" name="operation" value="xray-approve"/><input type="hidden" name="id" value={release.id}/>{release.prerelease && <label className="update-consent"><input type="checkbox" name="accept_prerelease" value="yes" required/>Разрешить предварительный выпуск {release.version}</label>}<button className="button" disabled={pending}>{pending ? "Одобрение…" : `Одобрить Xray ${release.version}`}</button>{state.message && <p role="status" className={`plan-feedback ${state.ok ? "" : "error"}`}>{state.message}</p>}</form>;
}
export function XrayInstall({ node, releases, requestKey, disabled }: { node: string; releases: XrayReleaseChoice[]; requestKey: string; disabled: boolean }) {
  const [state, action, pending] = useActionState(platformUpdateAction, { ok: false, message: "" });
  const [selected, setSelected] = useState(releases[0]?.id ?? "");
  const [key, setKey] = useState(requestKey);
  const selectedId = releases.some(r => r.id === selected) ? selected : "";
  const release = releases.find(r => r.id === selectedId);
  return <form action={action} className="update-action"><input type="hidden" name="operation" value="xray-install"/><input type="hidden" name="node_id" value={node}/><input type="hidden" name="request_key" value={key}/><label>Версия Xray<select name="id" value={selectedId} onChange={event => { setSelected(event.target.value); setKey(crypto.randomUUID()); }} disabled={pending || disabled}><option value="" disabled>{releases.length ? "Выберите версию" : "Нет более новой одобренной версии"}</option>{releases.map(r => <option key={r.id} value={r.id}>{r.version}{r.prerelease ? " · предварительный выпуск" : ""}</option>)}</select></label>{release?.prerelease && <label className="update-consent"><input type="checkbox" name="accept_prerelease" value="yes" required disabled={pending || disabled}/>Установить предварительный выпуск {release.version}</label>}<p className="muted">Во время перезапуска ядра соединения могут прерваться.</p><button className="button primary" disabled={pending || disabled || !release}>{pending ? "Запуск…" : release ? `Обновить Xray до ${release.version}` : "Обновление недоступно"}</button>{state.message && <p role="status" className={`plan-feedback ${state.ok ? "" : "error"}`}>{state.message}</p>}</form>;
}
