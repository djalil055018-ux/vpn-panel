"use server";
import { requireSession, replacePersonalSession, destroySession } from "@/lib/auth";
import { changeOwnMFA, ControlPlaneError } from "@/lib/control-plane";
import type { AdminSession } from "@/lib/admin-types";
import { redirect, unstable_rethrow } from "next/navigation";
import type { MFAActionState } from "@/lib/admin-mfa-types";

export async function ownMFAAction(_previous: MFAActionState, form: FormData): Promise<MFAActionState> {
  const session = await requireSession();
  if (session.legacy) return { ok: false, message: "Выйдите и войдите снова, чтобы настроить двухфакторный вход." };
  // Preserve only the user's existing setup display after a validation error.
  // Authorization always uses the server's encrypted pending secret, never this view.
  const prior = _previous?.enrollment;
  const enrollment = prior && typeof prior.secret === "string" && /^[A-Z2-7]{32}$/.test(prior.secret) && typeof prior.expires_at === "string" && Date.parse(prior.expires_at) > Date.now()
    ? { secret: prior.secret, expires_at: prior.expires_at, provisioning_url: `otpauth://totp/${encodeURIComponent(`VPN Platform:${session.user}`)}?${new URLSearchParams({ secret: prior.secret, issuer: "VPN Platform", algorithm: "SHA1", digits: "6", period: "30" })}` }
    : undefined;
  const operation = String(form.get("operation") ?? "");
  const password = String(form.get("password") ?? "");
  const factor = String(form.get("factor") ?? "").trim();
  if (!["enroll", "confirm", "disable", "recovery-codes"].includes(operation) || !password || Buffer.byteLength(password) > 1024 || factor.length > 64) return { ok: false, message: "Проверьте заполнение полей." };
  const body = { password, code: /^\d{6}$/.test(factor) ? factor : "", recovery_code: factor && !/^\d{6}$/.test(factor) ? factor : "" };
  if (operation === "confirm" && !body.code) return { ok: false, message: "Введите шесть цифр из приложения.", enrollment };
  try {
    if (operation === "enroll") {
      const enrollment = await changeOwnMFA<NonNullable<MFAActionState["enrollment"]>>(operation, body);
      return { ok: true, message: "Добавьте аккаунт в приложение и подтвердите код в течение 10 минут.", enrollment };
    }
    if (operation === "disable") {
      await changeOwnMFA<void>(operation, body);
      await destroySession();
      redirect("/login?mfa_disabled=1");
    }
    const value = await changeOwnMFA<{ recovery_codes: string[]; session_token: string; session: AdminSession }>(operation, body);
    await replacePersonalSession(value.session_token, value.session);
    // Returned only from the authenticated confirming action; never persisted
    // in browser storage, included in URLs, or exposed by the status endpoint.
    return { ok: true, message: "Сохраните резервные коды. Они показываются один раз. Остальные сеансы завершены.", recovery_codes: value.recovery_codes, completed: true };
  } catch (error) {
    unstable_rethrow(error);
    let message = "Не удалось изменить настройки. Повторите попытку позже.";
    if (error instanceof ControlPlaneError) {
      if (error.status === 400) message = "Код неверен, истёк или уже использован. Введите следующий код приложения либо неиспользованный резервный код.";
      if (error.status === 401) message = "Пароль неверен или сеанс завершён.";
      if (error.status === 409) message = "Настройки изменились. Обновите страницу и начните заново.";
      if (error.status === 429) message = "Слишком много попыток. Подождите минуту.";
    }
    return { ok: false, message, enrollment };
  }
}
