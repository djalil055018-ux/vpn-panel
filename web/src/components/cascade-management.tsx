"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState, useTransition } from "react";
import { cascadeAction, type CascadeActionState } from "@/app/cascade-actions";
import { cascadeAgentReady, cascadeStates, type Cascade, type CascadePlan, type CascadeService } from "@/lib/cascades";
import { NavIcon } from "@/components/ui/nav-icon";
import styles from "./cascade-management.module.css";

type Props = { tenant: string; cascades: Cascade[]; plans: CascadePlan[]; services: CascadeService[] };
function Route({ entry, exit, small = false }: { entry: string; exit: string; small?: boolean }) {
  return <div className={`${styles.route} ${small ? styles.smallRoute : ""}`} aria-label={`Клиент → ${entry} → ${exit} → Интернет`}>
    <div className={styles.endpoint}><NavIcon name="clients" width={22} height={22}/><span>Клиент</span></div><span className={styles.arrow} aria-hidden="true">→</span>
    <div className={styles.hop}><span className={styles.hopNumber}>01</span><div><small>ВХОДНОЙ СЕРВЕР</small><strong>{entry}</strong></div></div><span className={styles.arrow} aria-hidden="true">→</span>
    <div className={`${styles.hop} ${styles.exitHop}`}><span className={styles.hopNumber}>02</span><div><small>ВЫХОДНОЙ СЕРВЕР</small><strong>{exit}</strong></div></div><span className={styles.arrow} aria-hidden="true">→</span>
    <div className={styles.endpoint}><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/></svg><span>Интернет</span></div>
  </div>;
}

function Editor({ tenant, cascade, plans, services, onDone, onClose }: Omit<Props, "cascades"> & { cascade?: Cascade; onDone: (value: CascadeActionState) => void; onClose: () => void }) {
  const [name, setName] = useState(cascade?.name ?? "");
  const [entry, setEntry] = useState(cascade?.entry_service_id ?? "");
  const [exit, setExit] = useState(cascade?.exit_service_id ?? "");
  const [plan, setPlan] = useState(cascade?.plan_id ?? "");
  const [port, setPort] = useState(String(cascade?.entry_port ?? ""));
  const [enabled, setEnabled] = useState(cascade?.enabled ?? false);
  const [feedback, setFeedback] = useState<CascadeActionState>({ ok: false, message: "" });
  const [pending, start] = useTransition();
  const formRef = useRef<HTMLFormElement>(null), id = useId();
  const entryService = services.find(s => s.id === entry), exitService = services.find(s => s.id === exit);
  const runtimeChanged = !cascade || cascade.plan_id !== plan || cascade.entry_service_id !== entry || cascade.exit_service_id !== exit || cascade.entry_port !== Number(port) || cascade.enabled !== enabled;
  const applies = runtimeChanged && (enabled || cascade?.enabled);
  const agentsReady = entryService && exitService && cascadeAgentReady(entryService.agent_version) && cascadeAgentReady(exitService.agent_version);
  const canEnable = agentsReady && entryService?.enabled && exitService?.enabled && plans.find(p => p.id === plan)?.enabled;
  useEffect(() => { formRef.current?.querySelector<HTMLInputElement>('input[name="name"]')?.focus(); }, []);
  function submit(form: FormData) {
    start(async () => {
      try { const result = await cascadeAction(form); setFeedback(result); if (result.ok) onDone(result); }
      catch { setFeedback({ ok: false, message: "Связь прервалась. Обновите список, чтобы проверить результат." }); }
    });
  }
  return <section className={styles.editor} aria-labelledby={`${id}-heading`}>
    <div className={styles.editorHeading}><div><p className={styles.kicker}>{cascade ? "НАСТРОЙКИ МАРШРУТА" : "НОВЫЙ МАРШРУТ"}</p><h2 id={`${id}-heading`}>{cascade ? "Изменить каскад" : "Создать каскад"}</h2></div><button type="button" className="button ghost" disabled={pending} onClick={onClose}>Закрыть</button></div>
    <form ref={formRef} action={submit} className={styles.form} aria-busy={pending}>
      <input type="hidden" name="tenant_id" value={tenant}/><input type="hidden" name="cascade_id" value={cascade?.id ?? ""}/><input type="hidden" name="operation" value="save"/>
      <fieldset disabled={pending}>
        <div className={styles.fields}>
          <label className={styles.wide}>Название в подписке<input name="name" value={name} onChange={e => setName(e.target.value)} required maxLength={256} placeholder="🇳🇱 Через Финляндию → Нидерланды"/><span>Можно вставить флаг или эмодзи. Клиенты увидят именно это название.</span></label>
          <label>Группа клиентов<select name="plan_id" value={plan} onChange={e => setPlan(e.target.value)} required><option value="" disabled>Выберите группу</option>{plans.map(p => <option key={p.id} value={p.id}>{p.name}{p.enabled ? "" : " · отключена"}</option>)}</select><span>Доступ получат активные клиенты выбранной группы.</span></label>
          <label>Порт входного сервера<input name="entry_port" value={port} onChange={e => setPort(e.target.value)} required type="number" min={1} max={65535} placeholder="Например, 8443"/><span>Свободный TCP-порт, доступный из интернета. Порт 10085 зарезервирован.</span></label>
          <label>Входной сервер<select name="entry_service_id" value={entry} onChange={e => { setEntry(e.target.value); if (services.find(s => s.id === e.target.value)?.node_id === exitService?.node_id) setExit(""); }} required><option value="" disabled>Куда подключается клиент</option>{services.map(s => <option key={s.id} value={s.id}>{s.node_name} · {s.name}{s.enabled ? "" : " · отключён"}</option>)}</select><span>{entryService ? `Агент ${entryService.agent_version || "не зарегистрирован"} · сервис на порту ${entryService.port}` : "VLESS · TCP · REALITY"}</span></label>
          <label>Выходной сервер<select name="exit_service_id" value={exit} onChange={e => setExit(e.target.value)} required><option value="" disabled>Откуда трафик выйдет в интернет</option>{services.filter(s => s.node_id !== entryService?.node_id).map(s => <option key={s.id} value={s.id}>{s.node_name} · {s.name}{s.enabled ? "" : " · отключён"}</option>)}</select><span>{exitService ? `Агент ${exitService.agent_version || "не зарегистрирован"} · сервис на порту ${exitService.port}` : "Другой сервер с VLESS · TCP · REALITY"}</span></label>
        </div>
        <div className={styles.preview}><p className={styles.kicker}>ПРОФИЛЬ В ПОДПИСКЕ</p><strong>{name.trim() || "Название нового каскада"}</strong><Route entry={entryService?.node_name ?? "Выберите вход"} exit={exitService?.node_name ?? "Выберите выход"} small/></div>
        <label className={styles.check}><input name="enabled" type="checkbox" checked={enabled} disabled={!enabled && !canEnable} onChange={e => setEnabled(e.target.checked)}/><span><strong>Включить каскад</strong><small>Обычные подключения сохранятся. При недоступности выхода каскад не переключится на прямое соединение.</small></span></label>
        {!canEnable && <p className={styles.note}>Для включения выберите активную группу и два включённых сервиса. На обоих серверах нужен <Link href="/agent-updates">агент от 0.2.34</Link> и <Link href="/core-updates">Xray от 26.9.9</Link>. Пока можно сохранить настройки выключенными.</p>}
        {applies && <label className={`${styles.check} ${styles.consent}`}><input name="apply" type="checkbox" value="yes" required/><span>Применить конфигурацию на задействованных серверах. VPN на этих серверах может кратковременно переподключиться. Входной TCP-порт открыт в межсетевом экране.</span></label>}
        <div className={styles.formFooter}><p>{enabled ? "Профиль появится после применения обоими серверами." : "Выключенный каскад не меняет подключения клиентов."}</p><button className="button primary" disabled={pending || !services.length || !plans.length}>{pending ? "Сохранение…" : "Сохранить каскад"}</button></div>
      </fieldset>
      {feedback.message && <p className={feedback.ok ? styles.good : styles.bad} role="status">{feedback.message}</p>}
    </form>
  </section>;
}

function DeleteCascade({ tenant, cascade, onDone, onClose }: { tenant: string; cascade: Cascade; onDone: (value: CascadeActionState) => void; onClose: () => void }) {
  const [feedback, setFeedback] = useState<CascadeActionState>({ ok: false, message: "" });
  const [pending, start] = useTransition();
  return <section className={styles.editor} aria-label="Удаление каскада"><h2>Удалить «{cascade.name}»?</h2><p>Профиль исчезнет из подписок группы. Клиенты и обычные подключения сохранятся.{cascade.enabled ? " Конфигурация обоих серверов будет обновлена; возможно кратковременное переподключение VPN." : ""}</p>
    <form action={form => start(async () => { try { const result = await cascadeAction(form); setFeedback(result); if (result.ok) onDone(result); } catch { setFeedback({ ok: false, message: "Не удалось получить результат. Обновите список перед повтором." }); } })}>
      <input type="hidden" name="tenant_id" value={tenant}/><input type="hidden" name="cascade_id" value={cascade.id}/><input type="hidden" name="operation" value="delete"/>
      <label className={styles.check}><input type="checkbox" name="confirm" value="yes" required disabled={pending}/>Подтверждаю удаление каскада{cascade.enabled ? " и применение на серверах" : ""}</label>
      <div className={styles.buttons}><button className="button danger" disabled={pending}>{pending ? "Удаление…" : "Удалить каскад"}</button><button type="button" className="button ghost" disabled={pending} onClick={onClose}>Отмена</button></div>
      {feedback.message && <p className={styles.bad} role="status">{feedback.message}</p>}
    </form>
  </section>;
}

export function CascadeManagement({ tenant, cascades, plans, services }: Props) {
  const router = useRouter();
  const [editor, setEditor] = useState<{ operation: "create" | "edit" | "delete"; cascade?: Cascade } | null>(null);
  const [feedback, setFeedback] = useState<CascadeActionState>({ ok: true, message: "" });
  const [refreshing, refresh] = useTransition();
  const editorRef = useRef<HTMLDivElement>(null);
  const pending = cascades.some(c => c.state === "pending");
  useEffect(() => {
    if (!pending || editor) return;
    let rounds = 0;
    const timer = setInterval(() => { if (document.visibilityState === "visible" && rounds++ < 30) refresh(() => router.refresh()); }, 10_000);
    return () => clearInterval(timer);
  }, [pending, editor, router]);
  function open(value: NonNullable<typeof editor>) { setFeedback({ ok: true, message: "" }); setEditor(value); }
  useEffect(() => { if (editor) editorRef.current?.scrollIntoView({ block: "start", behavior: "smooth" }); }, [editor]);
  function done(result: CascadeActionState) { setFeedback(result); setEditor(null); }
  const compatibleNodes = new Set(services.map(s => s.node_id)).size;
  return <div className={styles.workspace}>
    <section className={styles.hero} aria-label="Как работает каскад"><div className={styles.heroHeading}><div><p className={styles.kicker}>ПОДКЛЮЧЕНИЕ В ДВА ШАГА</p><h2>Вы выбираете путь трафика</h2><p>Клиент подключается ко входному серверу, а интернет видит адрес выходного.</p></div><span className={styles.protocol}>VLESS · TCP · REALITY</span></div><Route entry="Входной сервер" exit="Выходной сервер"/></section>
    <div className={styles.metrics}><div><span>Всего каскадов</span><strong>{cascades.length}</strong></div><div><span>Применены на серверах</span><strong>{cascades.filter(c => c.state === "active").length}</strong></div><div><span>Серверов с REALITY</span><strong>{compatibleNodes}</strong></div></div>
    <div className={styles.toolbar}><div><h2>Ваши маршруты</h2><p>Отдельные профили для выбранных групп клиентов.</p></div><div className={styles.buttons}><button className="button ghost" disabled={refreshing || Boolean(editor)} onClick={() => refresh(() => router.refresh())}>{refreshing ? "Обновление…" : "Обновить"}</button><button className="button primary" disabled={Boolean(editor)} onClick={() => open({ operation: "create" })}>+ Создать каскад</button></div></div>
    {feedback.message && <p className={`${styles.feedback} ${feedback.ok ? styles.good : styles.bad}`} role="status">{feedback.message}</p>}
    {editor && <div ref={editorRef} className={styles.editorAnchor}>{editor.operation === "delete" && editor.cascade ? <DeleteCascade tenant={tenant} cascade={editor.cascade} onDone={done} onClose={() => setEditor(null)}/> : <Editor key={editor.cascade?.id ?? "new"} tenant={tenant} cascade={editor.cascade} plans={plans} services={services} onDone={done} onClose={() => setEditor(null)}/>}</div>}
    {compatibleNodes < 2 && <p className={styles.note}>Для каскада нужны два разных Xray-сервера с VLESS TCP REALITY. Добавьте или настройте их в разделе <Link href="/nodes">«Серверы»</Link>.</p>}
    {cascades.length === 0 && !editor && <section className={styles.empty}><span className={styles.emptyIcon}><NavIcon name="cascade" width={30} height={30}/></span><h3>Первый маршрут начинается здесь</h3><p>Выберите два сервера и группу. После включения у её клиентов появится дополнительный профиль.</p><button className="button ghost" onClick={() => open({ operation: "create" })}>Настроить маршрут →</button></section>}
    <div className={styles.list}>{cascades.map(c => { const status = cascadeStates[c.state] ?? { label: "Статус неизвестен", tone: "neutral", description: "Обновите страницу, чтобы проверить состояние каскада." }; return <article className={styles.card} key={c.id} aria-label={c.name}>
      <div className={styles.cardHeading}><div><p className={styles.kicker}>ОТДЕЛЬНЫЙ ПРОФИЛЬ</p><h3>{c.name}</h3></div><span className={`${styles.badge} ${styles[status.tone]}`}>{status.label}</span></div>
      <Route entry={c.entry_node_name} exit={c.exit_node_name} small/>
      <div className={styles.facts}><div><span>Группа</span><strong>{c.plan_name}</strong></div><div><span>Входной порт</span><strong>{c.entry_port} / TCP</strong></div><div><span>Конфигурация входа</span><strong>{c.entry_applied_generation} / {c.entry_desired_generation}</strong></div><div><span>Конфигурация выхода</span><strong>{c.exit_applied_generation} / {c.exit_desired_generation}</strong></div></div>
      <div className={styles.cardFooter}><p>{status.description}</p><div className={styles.buttons}><button className="button ghost" disabled={Boolean(editor)} onClick={() => open({ operation: "edit", cascade: c })}>Настроить</button><button className={styles.deleteButton} disabled={Boolean(editor)} onClick={() => open({ operation: "delete", cascade: c })} aria-label={`Удалить каскад ${c.name}`}>Удалить</button></div></div>
    </article>; })}</div>
  </div>;
}
