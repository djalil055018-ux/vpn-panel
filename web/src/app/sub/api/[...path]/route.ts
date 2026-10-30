import { customerBridge } from "@/lib/customer-bridge";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

async function handle(request: Request, context: { params: Promise<{ path: string[] }> }) {
  return customerBridge(request, (await context.params).path);
}

export { handle as GET, handle as POST, handle as DELETE };
