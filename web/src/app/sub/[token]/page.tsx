import { PublicSubscriptionPage, SubscriptionEmpty } from "@/components/public-subscription";
import type { PublicSubscription } from "@/lib/public-subscription";
export const dynamic = "force-dynamic";
async function loadSubscription(token: string): Promise<{ info: PublicSubscription; url: string } | "missing" | "unavailable"> {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(token)) return "missing";
  try {
    const response = await fetch(`${process.env.CONTROL_PLANE_URL ?? "http://127.0.0.1:8080"}/sub/${token}/info`, {
      cache: "no-store", redirect: "error", signal: AbortSignal.timeout(7000), headers: { Accept: "application/json" },
    });
    if (response.status === 404) return "missing";
    if (!response.ok) return "unavailable";
    const info: PublicSubscription = await response.json();
    const base = new URL(process.env.VPN_PLATFORM_PUBLIC_URL ?? "");
    if (!["https:", "http:"].includes(base.protocol) || base.username || base.password) return "unavailable";
    return { info, url: new URL(`/sub/${token}`, base.origin).href };
  } catch { return "unavailable"; }
}
export default async function SubscriptionPage({ params }: { params: Promise<{ token: string }> }) {
  const data = await loadSubscription((await params).token);
  if (typeof data === "string") return <SubscriptionEmpty kind={data} />;
  return <PublicSubscriptionPage info={data.info} subscriptionURL={data.url} commerceEnabled={Boolean(process.env.CUSTOMER_COMMERCE_ORIGIN)} />;
}
