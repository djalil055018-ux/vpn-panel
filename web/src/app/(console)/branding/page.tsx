import { requireSession } from "@/lib/auth";
import { getTenants, getTenantBranding } from "@/lib/control-plane";
import { BrandingForm } from "@/components/branding-form";
export const dynamic = "force-dynamic";
export default async function BrandingPage({ searchParams }: { searchParams: Promise<{ tenant?: string }> }) {
  await requireSession();const [tenants, query] = await Promise.all([getTenants(), searchParams]);const tenant = tenants.find(t => t.id === query.tenant) ?? tenants[0];if (!tenant) return <section className="panel empty">Сначала создайте владельца.</section>;
  let branding = null;try { branding = await getTenantBranding(tenant.id); } catch { /* Safe unavailable state. */ }
  return <><header className="page-header"><div><h1>Оформление кабинета</h1><p>Бренд и поддержка отдельно для каждого владельца.</p></div></header><form className="plan-tenant" method="get"><label>Владелец<select name="tenant" defaultValue={tenant.id}>{tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label><button className="button ghost">Показать</button></form><section className="panel portal-card">{branding ? <BrandingForm key={tenant.id} branding={branding} /> : <p className="alert error">Оформление временно недоступно.</p>}</section></>;
}
