import { requireSession } from "@/lib/auth";
import { getTenants, getTenantLimits } from "@/lib/control-plane";
import { TenantLimitForm } from "@/components/tenant-limit-form";
export const dynamic = "force-dynamic";
export default async function LimitsPage({ searchParams }: { searchParams: Promise<{ tenant?: string }> }) {
  await requireSession();const [tenants, query] = await Promise.all([getTenants(), searchParams]);const tenant = tenants.find(t => t.id === query.tenant) ?? tenants[0];let limits = null;if (tenant) { try { limits = await getTenantLimits(tenant.id); } catch { /* Show unavailable state. */ } }
  return <><header className="page-header"><div><h1>Лимиты владельцев</h1><p>Количество клиентов и тарифов для каждого отдельного пространства.</p></div></header>{tenant && <form className="plan-tenant" method="get"><label>Владелец<select name="tenant" defaultValue={tenant.id}>{tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label><button className="button ghost">Показать</button></form>}{limits ? <section className="panel"><div className="panel-header"><div><h2>{tenant?.name}</h2><p>Создано клиентов: {limits.clients}. Тарифов: {limits.plans}.</p></div></div><TenantLimitForm key={limits.tenant_id} limits={limits} /></section> : <p className="alert error">Не удалось загрузить лимиты. Проверьте выбранного владельца.</p>}<p className="plan-muted">Ограничения применяются к API и кабинету, в том числе при одновременных запросах. Трафик, скорость и число подключённых устройств здесь не ограничиваются.</p></>;
}
