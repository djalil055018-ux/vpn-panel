"use server";
import {requireSession} from "@/lib/auth";
import {getNodeSecurity,getNodeReadiness,saveNodeSecurity} from "@/lib/control-plane";
import type {NodeSecurityPolicy,NodeSecurityStatus,NodeReadiness} from "@/lib/node-security";
type Result={ok:true;security:NodeSecurityStatus;readiness:NodeReadiness|null;message:string}|{ok:false;message:string};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
async function owner(){if((await requireSession()).role!=="owner")throw new Error("owner required");}
export async function reloadNodeSecurityAction(id:string):Promise<Result>{
 await owner();if(!uuid.test(id))return{ok:false,message:"Неверная нода."};
 try{const[security,readiness]=await Promise.all([getNodeSecurity(id),getNodeReadiness(id).catch(()=>null)]);return{ok:true,security,readiness,message:"Состояние обновлено."};}catch{return{ok:false,message:"Не удалось получить результаты проверки."};}
}
export async function saveNodeSecurityAction(id:string,policy:NodeSecurityPolicy):Promise<Result>{
 await owner();if(!uuid.test(id)||!policy||!["audit","protect"].includes(policy.mode)||typeof policy.update_hold!=="boolean"||!Number.isSafeInteger(policy.revision)||policy.revision<0)return{ok:false,message:"Неверные параметры защиты."};
 try{const security=await saveNodeSecurity(id,policy);return{ok:true,security,readiness:null,message:"Настройка сохранена. Агент применит её и пришлёт результат в течение минуты."};}catch{return{ok:false,message:"Сохранить не удалось. Обновите состояние: политика могла измениться или обновление агента уже выполняется."};}
}
