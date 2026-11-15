import { installationOrigin } from "@/lib/installation-origin";
import {requireSession} from "@/lib/auth";
import {getNodeProtocolIngress} from "@/lib/control-plane";
import {NodeProtocolIngressManager} from "./node-protocol-ingress";
export async function NodeIngressSection({node}:{node:string}){
 if((await requireSession()).role!=="owner")return null;
 try{return <NodeProtocolIngressManager initial={await getNodeProtocolIngress(node)} origin={installationOrigin(process.env.VPN_PLATFORM_PUBLIC_URL)}/>;}catch{return <section className="panel"><h2>Резервные входы протоколов</h2><p>Не удалось получить состояние. Обновите страницу позже.</p></section>;}
}
