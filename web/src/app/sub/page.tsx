import { CustomerPortal } from "@/components/customer-portal";
import { SubscriptionEmpty } from "@/components/public-subscription";
export const dynamic = "force-dynamic";
export default function SubscriptionHelp() { return process.env.CUSTOMER_COMMERCE_ORIGIN ? <CustomerPortal /> : <SubscriptionEmpty kind="welcome" />; }
