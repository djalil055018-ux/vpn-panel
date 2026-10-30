import { AccessPlanManagement } from "@/components/access-plan-management";
import { requireSession } from "@/lib/auth";
import { getAccessPlan, getAccessPlans, getNodes, getTenants, getVPNClients, getVPNServices } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export default async function AccessPlansPage({ searchParams }: { searchParams: Promise<{ tenant?: string }> }) {
  await requireSession();
  const [tenants, query] = await Promise.all([getTenants(), searchParams]);
  const tenant = tenants.find(t => t.id === query.tenant) ?? tenants[0];
  if (!tenant) return <section className="panel empty">Сначала создайте владельца платформы.</section>;
  let data;
  try {
    const [plans, clients, nodes] = await Promise.all([getAccessPlans(tenant.id), getVPNClients(tenant.id), getNodes()]);
    const tenantNodes = nodes.filter(node => node.tenant_id === tenant.id);
    const [details, groups] = await Promise.all([Promise.all(plans.map(plan => getAccessPlan(plan.id))), Promise.all(tenantNodes.map(node => getVPNServices(node.id)))]);
    data = { plans: details, clients: clients.map(client => ({ id: client.id, name: `${client.name}${client.effective_status !== "active" ? " · неактивен" : ""}` })),
      services: groups.flatMap((group, i) => group.map(service => ({ id: service.id, name: `${tenantNodes[i].name} · ${service.name}${service.enabled ? "" : " · отключён"}` }))) };
  } catch {
    return <><header className="page-header"><h1>Группы доступа</h1></header><div className="alert error">Не удалось загрузить группы доступа. Проверьте доступность контура управления и обновите страницу.</div></>;
  }
  return <>
    <header className="page-header"><div><div className="eyebrow">УПРАВЛЕНИЕ ДОСТУПОМ</div><h1>Группы доступа</h1><p>Сервисы, клиенты и доступ на всех нодах выбранного владельца.</p></div><div className="header-count">{data.plans.length}</div></header>
    <form className="plan-tenant" method="get"><label>Владелец<select name="tenant" defaultValue={tenant.id}>{tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label><button className="button ghost">Показать</button></form>
    <AccessPlanManagement key={tenant.id} tenant={tenant.id} {...data} />
  </>;
}
