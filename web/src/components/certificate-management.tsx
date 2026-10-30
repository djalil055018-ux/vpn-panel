"use client";
import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { useRouter } from "next/navigation";
import { certificateAction } from "@/app/certificate-actions";

export type CertificateCard = {
  id: string; nodeName: string; domain: string; environment: string; status: string;
  canDelete: boolean;
  autoRenew: boolean; issuer?: string; fingerprint?: string; expires?: string; error: boolean;
  jobs: { id: string; operation: string; status: string; created_at: string }[];
};
const labels: Record<string, string> = { draft: "Не выпущен", pending: "В очереди", issuing: "Выпускается", active: "Действует", renewing: "Продлевается", deleting: "Удаляется", failed: "Ошибка", revoked: "В архиве", claimed: "Выполняется", completed: "Завершено", delete: "Удаление" };
function Submit({ children, disabled = false }: { children: ReactNode; disabled?: boolean }) {
  const { pending } = useFormStatus();
  return <button className="button primary" disabled={disabled || pending}>{pending ? "Отправка…" : children}</button>;
}
function Form({ operation, id, children }: { operation: string; id?: string; children: ReactNode }) {
  const [state, action] = useActionState(certificateAction, { ok: false, message: "" });
  return <form className="plan-form" action={action}><input type="hidden" name="operation" value={operation} /><input type="hidden" name="certificate_id" value={id ?? ""} />{children}{state.message && <p className={`plan-feedback${state.ok ? "" : " error"}`} role="status">{state.message}</p>}</form>;
}
export function CertificateManagement({ nodes, certificates }: { nodes: { id: string; name: string }[]; certificates: CertificateCard[] }) {
  const router = useRouter();
  return <>
    <section className="panel"><div className="panel-header"><div><h2>Новый сертификат</h2><p>Домен должен указывать на выбранную ноду, а порт 80 — быть доступен из интернета.</p></div><button className="button ghost" onClick={() => router.refresh()}>Обновить статусы</button></div>
      <Form operation="create">
        <label>Нода<select name="node_id" required defaultValue=""><option value="" disabled>Выберите ноду</option>{nodes.map(node => <option key={node.id} value={node.id}>{node.name}</option>)}</select></label>
        <label>Домен<input name="domain" required maxLength={253} placeholder="vpn.example.com" /></label>
        <label>Email для уведомлений<input type="email" name="contact_email" placeholder="Необязательно" /></label>
        <label>Среда<select name="environment" defaultValue="staging"><option value="staging">Тестовая (staging)</option><option value="production">Доверенный сертификат</option></select></label>
        <label className="plan-check"><input type="checkbox" name="auto_renew" defaultChecked /> Автопродление</label><Submit disabled={!nodes.length}>Добавить сертификат</Submit>
      </Form>
      <p className="certificate-note">Приватные ключи создаются и хранятся на ноде. Staging-сертификаты предназначены для проверки выпуска и не являются доверенными. Добавление сертификата не переключает VPN-сервис на TLS.</p>
    </section>
    {!certificates.length && <div className="panel empty">Сертификатов пока нет.</div>}
    <div className="plan-grid">{certificates.map(cert => {
      const busy = ["pending", "issuing", "renewing", "deleting"].includes(cert.status), archived = cert.status === "revoked";
      return <article className="panel" key={cert.id}><div className="panel-header"><div><h2>{cert.domain}</h2><p>{cert.nodeName} · {cert.environment === "production" ? "Доверенный" : "Тестовый"}</p></div><span className={`status ${cert.status === "active" ? "success" : cert.status === "failed" ? "danger" : "warning"}`}>{labels[cert.status] ?? cert.status}</span></div>
        <dl className="certificate-facts"><div><dt>Действует до</dt><dd>{cert.expires ? new Date(cert.expires).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" }) + " МСК" : "Ещё не выпущен"}</dd></div><div><dt>Издатель</dt><dd>{cert.issuer || "—"}</dd></div>{cert.fingerprint && <div><dt>Отпечаток SHA-256</dt><dd className="certificate-fingerprint">{cert.fingerprint}</dd></div>}</dl>
        {cert.error && <p className="certificate-note">Последняя операция завершилась ошибкой. Проверьте DNS домена и доступность порта 80 на ноде перед повторной попыткой.</p>}
        {!archived && <>
          <Form operation="auto-renew" id={cert.id}><label className="plan-check"><input type="checkbox" name="auto_renew" defaultChecked={cert.autoRenew} /> Продлевать автоматически</label><Submit>Сохранить настройку</Submit></Form>
          {(["draft", "failed"].includes(cert.status) || cert.status === "active") && <Form operation={cert.status === "active" ? "renew" : "issue"} id={cert.id}><Submit>{cert.status === "active" ? "Продлить сейчас" : "Выпустить"}</Submit></Form>}
          {busy && <p className="certificate-note">Нода выполняет задание. Обновите статусы через несколько секунд.</p>}
          <details className="plan-settings"><summary>Архивирование</summary><p className="plan-muted">Остановит управление и автопродление. Сохранённые файлы останутся на ноде; сертификат не отзывается у центра сертификации.</p><Form operation="archive" id={cert.id}><label className="plan-check"><input type="checkbox" name="confirm" value="yes" required /> Подтверждаю архивирование</label><Submit disabled={busy}>В архив</Submit></Form></details>
        </>}
        {cert.canDelete && <details className="plan-settings"><summary>Удалить сертификат и его файлы</summary><p className="plan-muted">Удалит сертификат и приватный ключ с ноды через агент. Сертификат, который используется службой или импортированной конфигурацией, удалить нельзя. Центр сертификации отдельно не уведомляется.</p><Form operation="delete" id={cert.id}><input type="hidden" name="domain" value={cert.domain} /><label>Введите домен для подтверждения<input name="confirm_domain" required autoComplete="off" /></label><label className="plan-check"><input type="checkbox" name="confirm_delete" value="yes" required /> Подтверждаю удаление файлов на ноде</label><Submit disabled={busy}>Поставить удаление в очередь</Submit></Form></details>}
        {!cert.canDelete && <p className="certificate-note">Удаление файлов появится после обновления агента этой ноды до версии 0.2.36.</p>}
        <details className="plan-settings"><summary>История операций ({cert.jobs.length})</summary>{cert.jobs.length ? <ul className="certificate-history">{cert.jobs.map(job => <li key={job.id}>{labels[job.operation] ?? job.operation} · {labels[job.status] ?? job.status} · {new Date(job.created_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" })}</li>)}</ul> : <p className="plan-muted">Операций ещё не было.</p>}</details>
      </article>;
    })}</div>
  </>;
}
