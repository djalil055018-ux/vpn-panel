import { ThemeSwitch } from "@/components/theme-switch";
import { PaukMark } from "@/components/ui/pauk-mark";
import {
  redirect,
} from "next/navigation";

import {
  loginAction,
} from "@/app/actions";

import {
  getSession,
} from "@/lib/auth";

import {
  ru,
} from "@/lib/i18n/ru";

export default async function LoginPage({
  searchParams,
}: {
  searchParams:
    Promise<{
      error?: string;
      changed?: string;
      mfa_disabled?: string;
    }>;
}) {
  const session =
    await getSession();

  if (session) {
    redirect(session.role === "monitor" ? "/monitor" : "/dashboard");
  }

  const query =
    await searchParams;

  return (
    <main className="login-screen"><div className="login-theme"><ThemeSwitch /></div><aside className="login-story"><span className="hero-kicker">PAUK / VPN MANAGEMENT</span><h2>Ваша сеть.<br />Ваши правила.</h2><p>Одна панель для серверов, клиентов и безопасного доступа. Всё важное — перед вами.</p><div className="login-story-lines" aria-hidden="true"><PaukMark /></div><span className="login-story-footer">Независимая инфраструктура начинается здесь.</span></aside>
      <section className="login-card">
        <div className="login-mark">
          <PaukMark />
        </div>

        <div>
          <div className="eyebrow">
            {ru.auth.controlPlane}
          </div>

          <h1>
            Добро пожаловать
          </h1>

          <p className="muted">
            Войдите, чтобы управлять вашей сетью.
          </p>
        </div>

        {query.error && (
          <div className="alert error">
            {ru.auth.invalidCredentials}
          </div>
        )}
        {query.mfa_disabled === "1" && <p role="status" className="plan-feedback">Двухфакторный вход отключён. Войдите снова.</p>}
        {query.changed === "1" && <p role="status" className="plan-feedback">Пароль изменён. Войдите с новым паролем.</p>}

        <form
          action={loginAction}
          className="login-form"
        >
          <label>
            {ru.auth.username}

            <input
              name="username"
              autoComplete="username"
              required
              maxLength={64}
              defaultValue="admin"
            />
          </label>

          <label>
            {ru.auth.password}

            <input
              type="password"
              name="password"
              autoComplete="current-password"
              maxLength={1024}
              required
              autoFocus
            />
          </label>

          <label>Код двухфакторного входа (если включён)<input name="factor" autoComplete="one-time-code" maxLength={64} placeholder="Код приложения или резервный код" /></label>

          <button
            className="button primary"
            type="submit"
          >
            {ru.auth.signIn}
          </button>
        </form>

        <div className="login-footer">
          {ru.auth.adminOnly}
        </div>
      </section>
    </main>
  );
}
