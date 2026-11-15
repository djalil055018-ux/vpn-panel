import "server-only";
import { Resolver } from "node:dns/promises";
import { request } from "node:http";
import { globallyRoutableIPv4, ownCoverDomain } from "@/lib/node-cover";

export async function nodeCoverReady(node: string, domain: string): Promise<boolean> {
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(node) || !ownCoverDomain(domain)) return false;
  try {
    const resolver = new Resolver({ timeout: 1400, tries: 1 });
    const addresses = await resolver.resolve4(domain);
    if (addresses.length !== 1 || !globallyRoutableIPv4(addresses[0])) return false;
    return await new Promise<boolean>(resolve => {
      const req = request({
        hostname: addresses[0],
        port: 80,
        method: "HEAD",
        path: "/.well-known/pauk-node-" + node,
        headers: { Host: domain },
        signal: AbortSignal.timeout(2200),
      }, response => {
        response.resume();
        resolve(response.statusCode === 204);
      });
      req.on("error", () => resolve(false));
      req.end();
    });
  } catch {
    return false;
  }
}
