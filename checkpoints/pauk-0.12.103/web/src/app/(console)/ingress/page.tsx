import { installationOrigin } from "@/lib/installation-origin";
import {requireSession} from "@/lib/auth";
import {getIngressConfig,getIngressProvisionOverview} from "@/lib/control-plane";
import {IngressManager} from "@/components/ingress-manager";
export const dynamic="force-dynamic";
export default async function IngressPage(){
 const session=await requireSession();if(session.role!=="owner")return <section className="panel"><h1>Резервные входы</h1><p>Настройки доступны владельцу панели.</p></section>;
 const [config,provision]=await Promise.all([getIngressConfig().catch(()=>null),getIngressProvisionOverview().catch(()=>null)]);
 return <><header className="page-header"><div><div className="eyebrow">ИНФРАСТРУКТУРА</div><h1>Резервные входы</h1><p>Доступ к панели, подпискам и VPN при недоступности одного из адресов.</p></div></header>{config?<IngressManager key={config.entries.map(entry=>entry.id).join(",")} initial={config} provision={provision} origin={installationOrigin(process.env.VPN_PLATFORM_PUBLIC_URL)}/>:<section className="panel"><p role="alert" className="alert error">Не удалось получить настройки. Обновите страницу позже.</p></section>}</>;
}
