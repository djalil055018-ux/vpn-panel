"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { destroySession, requireSession } from "@/lib/auth";
import { ControlPlaneError, revokeOwnAdminSession } from "@/lib/control-plane";

export async function revokeSessionAction(_previous: { ok: boolean; message: string }, form: FormData) {
  const session = await requireSession();
  if (session.legacy) return { ok: false, message: "Войдите заново, чтобы управлять сеансами." };
  const all = form.get("scope") === "all";
  const id = String(form.get("session_id") ?? "");
  if (!all && !/^[0-9a-f-]{36}$/i.test(id)) return { ok: false, message: "Не найден сеанс." };
  try { await revokeOwnAdminSession(all ? null : id); }
  catch (error) { return { ok: false, message: error instanceof ControlPlaneError && error.status === 404 ? "Этот сеанс уже завершён. Обновите страницу." : "Не удалось завершить сеанс. Повторите попытку." }; }
  if (all || id === session.sessionID) { await destroySession(); redirect("/login"); }
  revalidatePath("/account");
  return { ok: true, message: "Сеанс завершён." };
}
