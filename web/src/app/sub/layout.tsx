import type { Metadata } from "next";
import "./subscription.css";
import "./customer.css";
import "./commerce.css";
export const metadata: Metadata = {
  title: "Моя подписка · PAUK", description: "Подписка, устройства и подключение VPN",
  robots: { index: false, follow: false, nocache: true }, referrer: "no-referrer",
};
export default function SubscriptionLayout({ children }: { children: React.ReactNode }) { return children; }

