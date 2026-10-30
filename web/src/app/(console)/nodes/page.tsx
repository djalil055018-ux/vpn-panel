import Link from "next/link";
import { requireSession } from "@/lib/auth";
import { getLifecycle, getNodes, getVPNServices } from "@/lib/control-plane";
import { ServerDirectory } from "@/components/server-directory";
import { categoriesForNode } from "@/lib/device-categories";
export const dynamic = "force-dynamic";
export default async function NodesPage({ searchParams }: { searchParams: Promise<{ deleted?: string; deleted_notice?: string; device?: string }> }) {
  const session = await requireSession();
  const query = await searchParams;
  const deleted = query.deleted === "true";
  const category = query.device === "router" ? "router" : "smartphone";
  const nodes = await getNodes(deleted);
  const servers = await Promise.all(nodes.map(async node => {
    const [lifecycle, services] = await Promise.all([
      deleted ? Promise.resolve(null) : getLifecycle(node.id).catch(() => null),
      deleted ? Promise.resolve([]) : getVPNServices(node.id).catch(() => []),
    ]);
    return { node, lifecycle, categories: categoriesForNode(services.map(service => service.protocol), node.runtime_core) };
  }));
  const visibleServers = deleted ? servers : servers.filter(server => server.categories.includes(category));
  const smartphoneCount = servers.filter(server => server.categories.includes("smartphone")).length;
  const routerCount = servers.filter(server => server.categories.includes("router")).length;
  return <>
    <header className="page-header"><div><div className="eyebrow">ИНФРАСТРУКТУРА</div><h1>{deleted ? "Архив серверов" : category === "router" ? "Серверы (Роутер)" : "Серверы (Смартфоны)"}</h1><p>{deleted ? "История сохранена. Доступ удалённых серверов к панели отозван." : "Список сгруппирован по протоколам, подходящим для выбранного типа устройства."}</p></div><div className="header-actions">{!deleted && <nav className="device-category-switch" aria-label="Категория серверов"><Link href="/nodes?device=smartphone" className={`button${category === "smartphone" ? " primary" : " ghost"}`} aria-current={category === "smartphone" ? "page" : undefined}>Серверы (Смартфоны) <span>{smartphoneCount}</span></Link><Link href="/nodes?device=router" className={`button${category === "router" ? " primary" : " ghost"}`} aria-current={category === "router" ? "page" : undefined}>Серверы (Роутер) <span>{routerCount}</span></Link></nav>}<Link href={deleted ? "/nodes" : "/nodes?deleted=true"} className="button ghost">{deleted ? "Действующие серверы" : "Архив"}</Link><Link href="/nodes/new" className="button primary"><span aria-hidden="true">＋</span> Добавить сервер</Link></div></header>
    {query.deleted_notice === "1" && <p role="status" className="plan-feedback">Сервер удалён. Клиенты и история сохранены.</p>}
    <ServerDirectory servers={visibleServers} totalServers={servers.length} deleted={deleted} canDelete={session.role === "owner"} canRename={session.role === "owner"} canReboot={session.role === "owner"} />
  </>;
}
