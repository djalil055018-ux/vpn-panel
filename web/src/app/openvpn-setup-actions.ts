"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { importReviewedOpenVPN, approveReviewedOpenVPN, initializeOpenVPN } from "@/lib/control-plane";

export async function openvpnSetupAction(_previous: {ok: boolean;message: string}, data: FormData) {
  await requireSession();
  const operation=String(data.get("operation")??""), node=String(data.get("node_id")??"");
  try {
    let message="";
    if(operation==="import") {await importReviewedOpenVPN();message="Проверенная сборка добавлена в реестр. Для использования требуется одобрение.";}
    else if(operation==="approve") {await approveReviewedOpenVPN();message="Проверенная сборка одобрена. Изменения на нодах ещё не запускались.";}
    else if(operation==="initialize") {
      if(!/^[a-f0-9-]{36}$/i.test(node)) return {ok:false,message:"Не указана нода."};
      const result=await initializeOpenVPN(node);
      message=result.changed?"Начальная конфигурация отправлена агенту. Дождитесь совпадения поколений, затем настройте сервис и доступ.":"Нода уже настроена. Текущая конфигурация сохранена.";
      revalidatePath(`/nodes/${node}`);revalidatePath(`/nodes/${node}/control`);
    } else return {ok:false,message:"Неизвестная операция."};
    revalidatePath("/core-updates");revalidatePath("/nodes");
    return {ok:true,message};
  } catch {return {ok:false,message:"Не удалось выполнить действие. Проверьте регистрацию ноды, совместимость агента и одобрение проверенной сборки в разделе обновлений ядер."};}
}
