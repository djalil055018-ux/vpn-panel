import { RemnawaveActivationForm } from "@/components/remnawave-activation-form";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { getAccessPlans, getRemnawaveImports, getRemnawaveImportClients } from "@/lib/control-plane";
import { remnawaveStatusLabels } from "@/lib/remnawave-types";
export const dynamic = "force-dynamic";
export default async function RemnawaveClientsPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ after?: string | string[] }> }) {
  const session = await requireSession();
  if (session.role !== "owner") redirect(session.role === "monitor" ? "/monitor" : "/dashboard");
  const { id } = await params, query = await searchParams;
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id)) notFound();
  const cursor = query.after ?? "0";
  if (typeof cursor !== "string" || !/^[0-9]{1,16}$/.test(cursor) || !Number.isSafeInteger(Number(cursor))) notFound();
  const item = (await getRemnawaveImports()).find(value => value.id === id);
  if (!item) notFound();
  const [page, plans] = await Promise.all([
    getRemnawaveImportClients(id, Number(cursor)),
    item.state === "held" ? getAccessPlans(item.tenant_id) : Promise.resolve([]),
  ]);
  return <>
    <header className="page-header"><div><h1>Сохранённые клиенты Remnawave</h1><p>{item.report.source_origin} · всего {item.report.users}. {item.state === "active" ? "Перенос завершён." : "Доступ в новой панели заблокирован до завершения переноса."}</p></div><Link href="/migrations/remnawave">К снимкам</Link></header>
    {item.state === "held" && <section className="panel portal-card">
      <h2>Выдать доступ в PAUK</h2>
      <p>Выбранная группа определяет доступ к серверам. PAUK перенесёт сроки, статусы, лимиты с исходными правилами сброса, Telegram и устройства из снимка.</p>
      <RemnawaveActivationForm migration={id} digest={item.report.sha256} plans={plans.filter(plan => plan.enabled)} />
    </section>}
    <section className="panel"><div className="table-wrap"><table><thead><tr><th>Клиент</th><th>ID в Remnawave</th><th>Исходный статус</th><th>Новая панель</th></tr></thead><tbody>{page.clients.map(client => <tr key={client.client_id}><td>{client.name}</td><td>{client.source_user_id}</td><td>{remnawaveStatusLabels[client.source_status] ?? "Неизвестен"}</td><td>{client.deleted ? "Удалён из новой панели" : client.held ? "Ожидает переключения" : "Перенесён"}</td></tr>)}</tbody></table></div>{page.clients.length === 0 && <p>На этой странице нет клиентов.</p>}</section>
    <nav aria-label="Страницы импорта"><Link className="button ghost" href={`/migrations/remnawave/${id}`}>Начало списка</Link>{page.next_cursor !== null && <Link className="button primary" href={`/migrations/remnawave/${id}?after=${page.next_cursor}`}>Следующая страница</Link>}</nav>
  </>;
}
