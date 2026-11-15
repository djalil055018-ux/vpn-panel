"use server";
import {requireSession} from "@/lib/auth";
import {getNodeProtocolIngress,saveNodeProtocolIngress} from "@/lib/control-plane";
import type {NodeProtocolIngress} from "@/lib/protocol-ingress";
import {revalidatePath} from "next/cache";
type Result={ok:true;data:NodeProtocolIngress;message:string}|{ok:false;message:string};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
async function owner(){if((await requireSession()).role!=="owner")throw new Error("owner required");}
export async function reloadNodeIngressAction(node:string):Promise<Result>{await owner();if(!uuid.test(node))return {ok:false,message:"Неверная нода."};try{return {ok:true,data:await getNodeProtocolIngress(node),message:"Состояние обновлено."};}catch{return {ok:false,message:"Не удалось получить состояние входов."};}}
export async function saveNodeIngressAction(node:string,service:string|null,mode:string,revision:number):Promise<Result>{
 await owner();if(!uuid.test(node)||(service!==null&&!uuid.test(service))||!Number.isSafeInteger(revision)||revision<0||!(service?["inherit","direct","enabled"]:["legacy","direct","enabled"]).includes(mode))return {ok:false,message:"Проверьте выбранный режим."};
 try{const data=await saveNodeProtocolIngress(node,service,{mode,revision});revalidatePath(`/nodes/${node}`);revalidatePath(`/nodes/${node}/control`);return {ok:true,data,message:"Настройка сохранена. Дождитесь готовности входов и обновите подписку в приложении."};}catch{return {ok:false,message:"Сохранить не удалось. Обновите состояние: настройки могли измениться в другом окне."};}
}
