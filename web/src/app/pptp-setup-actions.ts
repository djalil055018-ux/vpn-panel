"use server";
import { revalidatePath } from "next/cache";
import { unstable_rethrow } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { importReviewedPPTP, approveReviewedPPTP, initializePPTP } from "@/lib/control-plane";

export async function pptpSetupAction(_previous: {ok: boolean;message: string}, data: FormData) {
  const session=await requireSession();
  if(session.role==="monitor") return {ok:false,message:"Для подготовки PPTP нужны права администратора."};
  const operation=String(data.get("operation")??""), node=String(data.get("node_id")??"");
  try {
    let message="";
    if(operation==="import") {await importReviewedPPTP();message="Проверенная сборка добавлена в реестр. Для использования требуется одобрение.";}
    else if(operation==="approve") {await approveReviewedPPTP();message="Проверенная сборка одобрена. Изменения на нодах ещё не запускались.";}
    else if(operation==="initialize") {
      if(!/^[a-f0-9-]{36}$/i.test(node)) return {ok:false,message:"Не указана нода."};
      const result=await initializePPTP(node);
      message=result.changed?"Начальная конфигурация отправлена агенту. Дождитесь совпадения поколений, затем настройте сервис и доступ.":"Нода уже настроена. Текущая конфигурация сохранена.";
      revalidatePath(`/nodes/${node}`);revalidatePath(`/nodes/${node}/control`);
    } else return {ok:false,message:"Неизвестная операция."};
    revalidatePath("/core-updates");revalidatePath("/nodes");
    return {ok:true,message};
  } catch(error) {unstable_rethrow(error);return {ok:false,message:"Не удалось выполнить действие. Проверьте регистрацию ноды, совместимость агента и одобрение проверенной сборки в разделе обновлений ядер."};}
}
