"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { getProtocolTemplateTargets, previewProtocolTemplate, applyProtocolTemplate, getProtocolTemplateApplication } from "@/lib/control-plane";
import type { TemplateApplicationInput } from "@/lib/protocol-templates";
import { localRealityTarget, ownCoverDomain } from "@/lib/node-cover";
import { nodeCoverReady } from "@/lib/node-cover-probe";
async function owner() {if((await requireSession()).role!=="owner")throw new Error("owner required");}
export async function templateTargetsAction(id:string) {
 await owner();
 try {
   const value = await getProtocolTemplateTargets(id);
   if (id === "vless-reality-vision") {
     for (const target of value.targets) {
       if (target.server_name) continue;
       const certificate = target.certificates.find(item => ownCoverDomain(item.name));
       if (!certificate) continue;
       target.public_address ||= certificate.name;
       target.server_name = certificate.name;
       target.reality_target = localRealityTarget;
     }
   }
   return {ok:true as const,value};
 }
 catch{return {ok:false as const,message:"Не удалось получить серверы. Обновите список."};}
}
async function readyLocalCover(id: string, input: TemplateApplicationInput) {
 if (id !== "vless-reality-vision" || input.reality_target !== localRealityTarget || !ownCoverDomain(input.server_name)) return true;
 const { targets } = await getProtocolTemplateTargets(id);
 const target = targets.find(item => item.node_id === input.node_id);
 return !!target?.certificates.some(item => item.name === input.server_name)
   && await nodeCoverReady(input.node_id, input.server_name);
}
export async function templatePreviewAction(id:string,input:TemplateApplicationInput) {
 await owner();
 try {
   if (!await readyLocalCover(id,input)) return {ok:false as const,message:"Сначала подготовьте HTTPS-страницу в управлении этой нодой."};
   return {ok:true as const,value:await previewProtocolTemplate(id,input)};
 }
 catch{return {ok:false as const,message:"Проверка не выполнена. Проверьте адрес, порт, сертификат и выбранные группы."};}
}
export async function templateApplyAction(id:string,input:TemplateApplicationInput) {
 await owner();
 try{
  if (!await readyLocalCover(id,input)) return {ok:false as const,message:"HTTPS-страница ноды недоступна. Проверьте её в управлении нодой."};
  const value=await applyProtocolTemplate(id,input);
  revalidatePath("/nodes/"+value.node_id+"/control");revalidatePath("/clients");
  return {ok:true as const,value};
 }catch{return {ok:false as const,message:"Результат запроса пока не подтверждён. Проверьте состояние; повторная отправка этого запроса не создаст второй сервис."};}
}
export async function templateStatusAction(key:string) {
 await owner();
 try{return {ok:true as const,value:await getProtocolTemplateApplication(key)};}
 catch{return {ok:false as const,message:"Пока не удалось получить состояние. Повторите проверку или откройте сервер."};}
}
