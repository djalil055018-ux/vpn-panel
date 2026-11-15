"use server";
import {createConnection} from "node:net";
import {requireSession} from "@/lib/auth";
import {getIngressConfig,saveIngressConfig,checkIngressEntry,checkIngressDNS} from "@/lib/control-plane";
import {getIngressProvisionOverview,queueIngressProvision,cancelIngressProvision} from "@/lib/control-plane";
import {revalidatePath} from "next/cache";
import type {IngressConfig,IngressSettings,IngressDNS} from "@/lib/ingress-types";
type Result<T>={ok:true;data:T;message:string}|{ok:false;message:string};
async function owner(){if((await requireSession()).role!=="owner")throw new Error("owner required");}
export async function saveIngressAction(input:IngressSettings):Promise<Result<IngressConfig>>{
 await owner();
 if(!Number.isSafeInteger(input.revision)||!Number.isInteger(input.probe_interval_seconds)||input.probe_interval_seconds<10||input.probe_interval_seconds>300||typeof input.vpn_enabled!=="boolean"||typeof input.web_enabled!=="boolean"||typeof input.primary_id!=="string"||typeof input.secondary_id!=="string")return {ok:false,message:"Проверьте выбранные входы и интервал от 10 до 300 секунд."};
 try{const data=await saveIngressConfig(input);revalidatePath("/ingress");return {ok:true,data,message:"Настройки сохранены. Клиентам нужно обновить подписку; для веб-доступа проверьте DNS ниже."};}catch{return {ok:false,message:"Не удалось сохранить. Настройки могли измениться в другом окне — обновите страницу и повторите."};}
}
export async function checkIngressEntryAction(id:string):Promise<Result<IngressConfig>>{
 await owner();if(!/^[A-Za-z0-9_-]{3,64}$/.test(id))return {ok:false,message:"Некорректный вход."};
 try{const data=await checkIngressEntry(id);return {ok:true,data,message:"Проверка с сервера панели завершена. Доступность из мобильной сети может отличаться."};}catch{return {ok:false,message:"Проверка не завершена. Действующие подключения продолжают работать."};}
}
export async function checkIngressDNSAction():Promise<Result<IngressDNS>>{
 await owner();try{return {ok:true,data:await checkIngressDNS(),message:"DNS проверен с сервера панели."};}catch{return {ok:false,message:"Не удалось проверить DNS. Повторите позже."};}
}
export async function reloadIngressAction():Promise<Result<IngressConfig>>{
 await owner();try{return {ok:true,data:await getIngressConfig(),message:"Сведения обновлены."};}catch{return {ok:false,message:"Не удалось получить настройки."};}
}

export async function ingressProvisionOverviewAction():Promise<Result<import("@/lib/ingress-types").IngressProvisionOverview>>{await owner();try{return {ok:true,data:await getIngressProvisionOverview(),message:"Состояние подготовки обновлено."};}catch{return {ok:false,message:"Не удалось получить состояние подготовки."};}}
export async function queueIngressProvisionAction(node:string,address:string,key:string):Promise<Result<import("@/lib/ingress-types").IngressProvisionOverview>>{await owner();if(!/^[0-9a-f-]{36}$/.test(node)||!/^[0-9a-f-]{36}$/.test(key)||!/^\d{1,3}(\.\d{1,3}){3}$/.test(address))return {ok:false,message:"Выберите сервер и его публичный IP."};try{await queueIngressProvision(node,address,key);revalidatePath("/ingress");return {ok:true,data:await getIngressProvisionOverview(),message:"Подготовка запущена. Статус обновляется автоматически."};}catch{return {ok:false,message:"Не удалось запустить подготовку. Проверьте связь с агентами, выбранный адрес и отсутствие другой активной операции."};}}
export async function cancelIngressProvisionAction(id:string):Promise<Result<import("@/lib/ingress-types").IngressProvisionOverview>>{await owner();if(!/^[0-9a-f-]{36}$/.test(id))return {ok:false,message:"Некорректное задание."};try{await cancelIngressProvision(id);return {ok:true,data:await getIngressProvisionOverview(),message:"Подготовка отменена. Агент удалит настройки этого незавершённого входа."};}catch{return {ok:false,message:"Не удалось отменить подготовку. Обновите состояние."};}}

const deletionMessages: Record<string, string> = {
 stale: "Список входов изменился. Обновите страницу и повторите.",
 enabled: "Перед удалением отключите резерв для VPN, панели и подписок и сохраните настройки.",
 in_use: "Адрес входа ещё используется в VPN-профиле или DNS.",
 running: "Дождитесь завершения подготовки входа.",
 missing: "Вход уже удалён. Обновите страницу.",
 dns_unavailable: "Не удалось проверить DNS. Повторите позже.",
};

async function removePreparedIngress(id: string, revision: number): Promise<string> {
 return new Promise((resolve, reject) => {
  const socket = createConnection("/run/pauk-ingress-delete.sock");
  let response = "";
  socket.setEncoding("utf8");
  socket.setTimeout(12000, () => socket.destroy(new Error("ingress delete timeout")));
  socket.on("error", reject);
  socket.on("connect", () => socket.write(JSON.stringify({id, revision}) + "\n"));
  socket.on("data", (chunk: string) => {
   response += chunk;
   if (response.length > 1024) socket.destroy(new Error("invalid ingress delete response"));
  });
  socket.on("end", () => {
   try { resolve(JSON.parse(response).status); }
   catch (error) { reject(error); }
  });
 });
}

export async function deleteIngressEntryAction(id: string, revision: number): Promise<Result<IngressConfig>> {
 await owner();
 if (typeof id !== "string" || !/^[A-Za-z0-9_-]{3,64}$/.test(id) ||
     !Number.isSafeInteger(revision) || revision < 1) {
  return {ok:false,message:"Некорректный вход. Обновите страницу."};
 }
 try {
  const status = await removePreparedIngress(id, revision);
  if (status !== "ok") {
   return {ok:false,message:deletionMessages[status] ?? "Не удалось удалить вход. Обновите страницу и повторите."};
  }
  try {
   return {ok:true,data:await getIngressConfig(),message:"Вход удалён."};
  } catch {
   return {ok:false,message:"Вход удалён. Обновите страницу, чтобы получить новый список."};
  }
 } catch {
  return {ok:false,message:"Не удалось проверить результат удаления. Обновите страницу."};
 }
}
