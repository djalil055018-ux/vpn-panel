import { TenantAPIManagement } from "@/components/tenant-api-management";
import Link from "next/link";
import { requireSession } from "@/lib/auth";
import { getTenants, getTenantAPICredentials } from "@/lib/control-plane";

export const dynamic = "force-dynamic";
async function snapshot(tenant: string) { return { credentials: await getTenantAPICredentials(tenant), at: Date.now() }; }
export default async function APIAccessPage({ searchParams }: { searchParams: Promise<{ tenant?: string }> }) {
  await requireSession();
  const [tenants, query] = await Promise.all([getTenants(), searchParams]);
  const tenant = tenants.find(item => item.id === query.tenant) ?? tenants[0];
  if (!tenant) return <section className="panel empty">Сначала создайте владельца платформы.</section>;
  let data = null;
  try { data = await snapshot(tenant.id); } catch { /* Display a safe unavailable state below. */ }
  return <>
    <header className="page-header"><div><h1>Доступ к API</h1><p>Ключи интеграций и права доступа владельцев.</p></div><Link href="/portal/login" target="_blank" rel="noopener noreferrer" className="button ghost">Кабинет владельца</Link></header>
    <form className="plan-tenant" method="get"><label>Владелец<select name="tenant" defaultValue={tenant.id}>{tenants.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><button className="button ghost">Показать</button></form>
    {data ? <TenantAPIManagement key={tenant.id} tenant={tenant.id} {...data} /> : <div className="alert error">Не удалось загрузить ключи. Обновите страницу позже.</div>}
  </>;
}
