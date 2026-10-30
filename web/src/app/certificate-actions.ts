"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, certificateOperation, createNodeCertificate } from "@/lib/control-plane";

export async function certificateAction(_previous: { ok: boolean; message: string }, form: FormData) {
  await requireSession();
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const operation = field("operation"), id = field("certificate_id"), node = field("node_id");
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  try {
    if (operation === "create") {
      const domain = field("domain").toLowerCase().replace(/\.$/, ""), environment = field("environment"), email = field("contact_email");
      if (!uuid.test(node) || !domain || domain.length > 253 || !["staging", "production"].includes(environment)) return { ok: false, message: "Выберите ноду, укажите домен и среду выпуска." };
      await createNodeCertificate(node, { domain, environment, auto_renew: form.has("auto_renew"), ...(email ? { contact_email: email } : {}) });
    } else {
      if (!uuid.test(id)) return { ok: false, message: "Некорректный сертификат." };
      if (!["issue", "renew", "archive", "auto-renew", "delete"].includes(operation)) return { ok: false, message: "Неизвестная операция." };
      if (operation === "archive" && field("confirm") !== "yes") return { ok: false, message: "Подтвердите архивирование сертификата." };
      if (operation === "delete" && (field("confirm_domain") !== field("domain") || field("confirm_delete") !== "yes")) return { ok: false, message: "Введите точное доменное имя и подтвердите удаление." };
      await certificateOperation(id, operation as "issue" | "renew" | "archive" | "auto-renew" | "delete", form.has("auto_renew"), field("confirm_domain"));
    }
    revalidatePath("/certificates");
    return { ok: true, message: operation === "issue" || operation === "renew" ? "Задание отправлено на ноду. Обновите страницу, чтобы проверить результат." : operation === "delete" ? "Удаление поставлено в очередь на ноду. Сертификат исчезнет из списка после завершения." : operation === "create" ? "Сертификат добавлен. После проверки домена нажмите «Выпустить»." : "Изменения сохранены." };
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      if (error.status === 409) return { ok: false, message: "Удаление невозможно: проверьте, что сертификат не используется службой, на ноде обновлён агент, нет активной операции и домен подтверждён точно." };
      if (error.status === 400) return { ok: false, message: "Проверьте домен и email. Поддерживается HTTP-01 для обычного доменного имени, без wildcard." };
      if (error.status === 404) return { ok: false, message: "Нода или сертификат не найден. Обновите страницу." };
    }
    return { ok: false, message: "Не удалось выполнить действие. Обновите страницу и проверьте состояние операции." };
  }
}
