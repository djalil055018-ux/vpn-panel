import {
  Sidebar,
} from "@/components/sidebar";
import { redirect } from "next/navigation";
import { ThemeSwitch } from "@/components/theme-switch";

import {
  requireSession,
} from "@/lib/auth";

export const dynamic =
  "force-dynamic";

export default async function ConsoleLayout({
  children,
}: {
  children:
    React.ReactNode;
}) {
  const session =
    await requireSession();
  if (session.role === "monitor") redirect("/monitor");

  return (
    <div className="app-shell">
      <Sidebar
        user={session.user}
        role={session.role}
      />

      <main className="content" id="main-content">
        <div className="workspace-toolbar"><span>Рабочее пространство <span aria-hidden="true">/</span> <strong>PAUK</strong></span><ThemeSwitch /></div>
        {children}
      </main>
    </div>
  );
}
