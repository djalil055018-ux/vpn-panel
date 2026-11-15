import {randomUUID} from "crypto";
import {AutoProfileRefresh} from "@/components/auto-profile-refresh";
import {getAutoProfileRefresh} from "@/lib/control-plane";
import { requireSession } from "@/lib/auth";
import { getTenants, getAutoProfile } from "@/lib/control-plane";
import { AutoProfileForm, AutoProfileHelp } from "@/components/auto-profile-form";
export const dynamic = "force-dynamic";
export default async function AutoProfilePage({ searchParams }: { searchParams: Promise<{ tenant?: string }> }) {
  const session=await requireSession();
  const [tenants, query] = await Promise.all([getTenants(), searchParams]);
  const tenant = tenants.find(t => t.id === query.tenant) ?? tenants[0];
  if (!tenant) return <section className="panel empty">Сначала создайте владельца.</section>;
  let settings = null;
  try { settings = await getAutoProfile(tenant.id); } catch { /* Explicit unavailable state; never save guessed settings. */ }
  let refresh=null;
  if(session.role==="owner"){try{refresh=await getAutoProfileRefresh(tenant.id);}catch{}}
  return <>
    <header className="page-header"><div><div className="eyebrow">ПОДКЛЮЧЕНИЕ БЕЗ ЛИШНИХ НАСТРОЕК</div><h1>Автоматический профиль</h1><p>Распределение клиентов и маршрутизация — в одном подключении.</p></div></header>
    <form className="plan-tenant" method="get"><label>Владелец<select name="tenant" defaultValue={tenant.id}>{tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label><button className="button ghost">Показать</button></form>
    <section className="panel auto-profile-panel">{settings ? <AutoProfileForm key={tenant.id} settings={settings} /> : <p className="alert error">Настройки временно недоступны. Обновите страницу позже.</p>}</section>
    {settings&&session.role==="owner"&&(refresh?<AutoProfileRefresh key={tenant.id} tenant={tenant.id} name={settings.name} enabled={settings.enabled} initial={refresh} requestKey={randomUUID()}/>:<section className="panel"><p className="alert error">Сведения об обновлениях временно недоступны. Обновите страницу позже.</p></section>)}
    <AutoProfileHelp />
  </>;
}
