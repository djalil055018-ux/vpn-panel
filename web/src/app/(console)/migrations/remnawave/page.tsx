import { RemnawaveSnapshotForm } from "@/components/remnawave-snapshot-form";
import Link from "next/link";
import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { getRemnawaveImports, getTenants } from "@/lib/control-plane";
import { remnawaveReviewLabels, remnawaveResetLabels, remnawaveStatusLabels } from "@/lib/remnawave-types";

export const dynamic = "force-dynamic";
export default async function RemnawavePage() {
  const session = await requireSession();
  if (session.role !== "owner") redirect(session.role === "monitor" ? "/monitor" : "/dashboard");
  const [imports, tenants] = await Promise.all([getRemnawaveImports(), getTenants()]);
  return <>
    <header className="page-header"><div><div className="eyebrow">ПЕРЕНОС КЛИЕНТОВ</div><h1>Перенос Remnawave</h1><p>Снимки исходной панели, сохранённые клиенты и проверки перед переключением.</p></div></header>
    <section className="panel portal-card">
      <h2>Импорт клиентов</h2>
      <p>Выберите владельца в PAUK и загрузите JSON-снимок Remnawave 3.4.3 или 3.4.11. Перед импортом панель покажет число клиентов и устройств.</p>
      <RemnawaveSnapshotForm owners={tenants.map(({id, name}) => ({id, name}))} />
    </section>
    {imports.length === 0 && <section className="panel"><h2>Снимков пока нет</h2></section>}
    {imports.map(item => <section className="panel" key={item.id}>
      <div className="panel-header"><div><h2>{item.report.source_origin}</h2><p>{tenants.find(tenant => tenant.id === item.tenant_id)?.name ?? "Владелец недоступен"} · снимок {new Date(item.report.captured_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" })} МСК</p></div><span className={item.state === "active" ? "plan-feedback" : "operations-warning"}>{item.state === "active" ? "Перенос завершён" : item.state === "activating" ? "Проверяется переключение" : item.state === "rollback_required" ? "Требуется восстановление" : "Ожидает переключения"}</span></div>
      <p><strong>{item.report.users}</strong> клиентов сохранено · <strong>{item.report.subscription_urls}</strong> исходных подписок · <strong>{item.report.devices}</strong> зарегистрированных устройств</p>
      <p>В исходной панели: {Object.entries(item.report.status_counts).map(([status, count]) => `${remnawaveStatusLabels[status] ?? "Другой статус"}: ${count}`).join(" · ")}.</p>
      <p>Сброс трафика: {Object.entries(item.report.reset_policy_counts).map(([policy, count]) => `${remnawaveResetLabels[policy] ?? "Другое правило"}: ${count}`).join(" · ")}.</p>
      {item.state !== "active" && <><h3>Перед переключением</h3><ul>{item.report.required_review.map(code => <li key={code}>{remnawaveReviewLabels[code] ?? "Проверить дополнительное условие переноса."}</li>)}</ul></>}
      <Link className="button primary" href={`/migrations/remnawave/${item.id}`}>Сохранённые клиенты</Link>
      <details><summary>Идентификатор снимка</summary><code style={{ overflowWrap: "anywhere" }}>{item.report.sha256}</code></details>
    </section>)}
  </>;
}
