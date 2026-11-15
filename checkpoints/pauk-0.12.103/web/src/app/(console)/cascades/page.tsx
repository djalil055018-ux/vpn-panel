import { CascadeManagement } from "@/components/cascade-management";
import { requireSession } from "@/lib/auth";
import { getAccessPlans, getCascades, getNodes, getTenants, getVPNServices } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export default async function CascadesPage({ searchParams }: { searchParams: Promise<{ tenant?: string }> }) {
  const session = await requireSession();
  if (session.role === "monitor") return <section className="panel empty">Настройка каскадов доступна владельцу и администратору.</section>;
  async function load() {
    const [tenants, query] = await Promise.all([getTenants(), searchParams]);
    const tenant = tenants.find(t => t.id === query.tenant) ?? tenants[0];
    if (!tenant) return null;
    const [cascades, plans, nodes] = await Promise.all([getCascades(tenant.id), getAccessPlans(tenant.id), getNodes()]);
    const tenantNodes = nodes.filter(n => n.tenant_id === tenant.id && n.runtime_core === "xray" && n.status !== "retired");
    const groups = await Promise.all(tenantNodes.map(node => getVPNServices(node.id)));
    const services = groups.flatMap((group, i) => group.filter(s => s.protocol === "vless" && s.transport === "tcp" && s.security === "reality").map(s => ({ id: s.id, name: s.name, node_id: s.node_id, node_name: tenantNodes[i].name, agent_version: tenantNodes[i].agent_version ?? "", enabled: s.enabled, port: s.port })));
    return { tenants, tenant, cascades, plans, services };
  }
  const data = await load().catch(() => undefined);
  if (data === undefined) return <><header className="page-header"><h1>Каскады серверов</h1></header><div className="alert error">Не удалось загрузить каскады. Обновите страницу после восстановления связи с панелью.</div></>;
  if (data === null) return <section className="panel empty">Сначала создайте владельца платформы.</section>;
  const { tenants, tenant, cascades, plans, services } = data;
  return <>
      <header className="page-header"><div><div className="eyebrow">МАРШРУТЫ ПОДКЛЮЧЕНИЯ</div><h1>Каскады серверов</h1><p>Два сервера, один профиль. Управляйте маршрутом клиентов через выбранную группу.</p></div></header>
      {tenants.length > 1 && <form className="plan-tenant" method="get"><label>Владелец<select name="tenant" defaultValue={tenant.id}>{tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label><button className="button ghost">Показать</button></form>}
      <CascadeManagement key={tenant.id} tenant={tenant.id} cascades={cascades} plans={plans.map(p => ({ id: p.id, name: p.name, enabled: p.enabled }))} services={services}/>
    </>;
}
