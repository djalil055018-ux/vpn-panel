import type {
  Metadata,
} from "next";

import "./globals.css";
import "./design.css";
import "./clients-table.css";
import { cookies } from "next/headers";
import { ThemeProvider } from "@/components/theme-switch";

export const metadata: Metadata = {
  title:
    "PAUK — панель управления VPN",
  description:
    "Панель управления VPN-инфраструктурой",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children:
    React.ReactNode;
}>) {
  const theme = (await cookies()).get("pauk_theme")?.value === "dark" ? "dark" : "light";
  return (
    <html lang="ru" data-theme={theme}>
      <body>
        <ThemeProvider initialTheme={theme}>{children}</ThemeProvider>
      </body>
    </html>
  );
}
