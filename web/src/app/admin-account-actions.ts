"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { destroySession, requireSession } from "@/lib/auth";
import { changeAdminPassword, ControlPlaneError, createAdminAccount, resetAdminPassword, updateAdminAccount } from "@/lib/control-plane";
import type { AdminRole } from "@/lib/admin-types";

export type AdminActionState = { ok: boolean; message: string };
function role(value: string): value is AdminRole { return ["owner", "admin", "monitor"].includes(value); }
function validPassword(value: string) { return [...value].length >= 15 && Buffer.byteLength(value, "utf8") <= 1024; }
function failure(error: unknown): AdminActionState {
  let message = "Не удалось сохранить изменения. Повторите попытку.";
  if (error instanceof ControlPlaneError) {
    if (error.status === 409) message = "Имя уже занято либо изменение оставит панель без активного владельца.";
    if (error.status === 403) message = "У вашей учётной записи нет прав на это действие.";
    if (error.status === 401) message = "Сеанс завершён или текущий пароль неверен.";
    if (error.status === 429) message = "Слишком много попыток. Подождите минуту.";
  }
  return { ok: false, message };
}

export async function adminAccountAction(_previous: AdminActionState, form: FormData): Promise<AdminActionState> {
  const session = await requireSession();
  if (session.role !== "owner") return { ok: false, message: "Управление аккаунтами доступно владельцу." };
  const operation = String(form.get("operation") ?? "");
  const id = String(form.get("id") ?? "");
  const selectedRole = String(form.get("role") ?? "");
  const password = String(form.get("password") ?? "");
  if (operation !== "create" && !/^[0-9a-f-]{36}$/i.test(id)) return { ok: false, message: "Не найден аккаунт." };
  try {
    if (operation === "create") {
      const username = String(form.get("username") ?? "").trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(username) || !role(selectedRole) || !validPassword(password)) return { ok: false, message: "Укажите имя, роль и пароль от 15 символов (до 1024 байт)." };
      await createAdminAccount({ username, role: selectedRole, password });
    } else if (operation === "update") {
      if (!role(selectedRole)) return { ok: false, message: "Выберите роль." };
      await updateAdminAccount(id, { role: selectedRole, enabled: form.get("enabled") === "on" });
    } else if (operation === "password") {
      if (!validPassword(password)) return { ok: false, message: "Пароль должен содержать от 15 символов (до 1024 байт)." };
      await resetAdminPassword(id, password);
    } else return { ok: false, message: "Неизвестное действие." };
  } catch (error) { return failure(error); }
  if (id === session.accountID) { await destroySession(); redirect("/login"); }
  revalidatePath("/administrators");
  return { ok: true, message: operation === "create" ? "Аккаунт создан." : "Изменения сохранены. При изменении роли, доступа или пароля сеансы отозваны." };
}

export async function ownPasswordAction(_previous: AdminActionState, form: FormData): Promise<AdminActionState> {
  const session = await requireSession();
  if (session.legacy) return { ok: false, message: "Выйдите и войдите снова, чтобы изменить пароль." };
  const current = String(form.get("current_password") ?? "");
  const password = String(form.get("new_password") ?? "");
  if (!validPassword(password) || password !== String(form.get("repeat_password") ?? "")) return { ok: false, message: "Новый пароль: от 15 символов, до 1024 байт. Повтор должен совпадать." };
  try { await changeAdminPassword(current, password); } catch (error) { return failure(error); }
  await destroySession();
  redirect("/login?changed=1");
}
