import {requireSession} from "@/lib/auth";
import {getNodeSecurity,getNodeReadiness} from "@/lib/control-plane";
import {NodeSecurityManager} from "./node-security";
export async function NodeSecuritySection({node}:{node:string}){
 if((await requireSession()).role!=="owner")return null;
 try{const[security,readiness]=await Promise.all([getNodeSecurity(node),getNodeReadiness(node).catch(()=>null)]);return <NodeSecurityManager initial={security} initialReadiness={readiness}/>;}
 catch{return <section className="panel"><h2>Безопасность и готовность</h2><p>Не удалось получить состояние. Обновите страницу позже.</p></section>;}
}
