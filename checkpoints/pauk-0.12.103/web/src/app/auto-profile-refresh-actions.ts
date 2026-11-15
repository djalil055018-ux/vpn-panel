"use server";
import {revalidatePath} from "next/cache";
import {requireSession} from "@/lib/auth";
import {ControlPlaneError,getAutoProfileRefresh,saveAutoProfileRefreshSchedule,refreshAutoProfile} from "@/lib/control-plane";
import type {AutoRefreshSchedule} from "@/lib/auto-profile-refresh";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
async function owner(tenant:string){return uuid.test(tenant)&&(await requireSession()).role==="owner";}
export async function autoRefreshStatusAction(tenant:string){
 if(!await owner(tenant))return {ok:false as const,message:"Управление обновлениями доступно владельцу панели."};
 try{return {ok:true as const,value:await getAutoProfileRefresh(tenant)};}catch{return {ok:false as const,message:"Не удалось загрузить состояние обновлений."};}
}
export async function autoRefreshScheduleAction(tenant:string,input:Pick<AutoRefreshSchedule,"enabled"|"daily_time"|"revision">){
 if(!await owner(tenant))return {ok:false as const,message:"Управление обновлениями доступно владельцу панели."};
 if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(input.daily_time)||!Number.isSafeInteger(input.revision)||input.revision<0)return {ok:false as const,message:"Выберите время от 00:00 до 23:59."};
 try{await saveAutoProfileRefreshSchedule(tenant,input);revalidatePath("/auto-profile");return {ok:true as const,value:await getAutoProfileRefresh(tenant)};}
 catch(e){return {ok:false as const,message:e instanceof ControlPlaneError&&e.status===409?"Настройки изменились в другом окне. Обновите состояние перед сохранением.":"Ответ не получен. Обновите состояние, чтобы проверить сохранённое расписание."};}
}
export async function autoRefreshRunAction(tenant:string,key:string){
 if(!await owner(tenant)||!uuid.test(key))return {ok:false as const,message:"Обновите страницу и повторите запрос."};
 try{const run=await refreshAutoProfile(tenant,key);revalidatePath("/auto-profile");return {ok:true as const,run,value:await getAutoProfileRefresh(tenant)};}
 catch{return {ok:false as const,message:"Ответ не получен. Повторная отправка проверит тот же запрос и не выполнит обновление дважды."};}
}
