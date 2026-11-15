import "server-only";

import { spawn } from "node:child_process";

const maxSnapshotBytes = 64 * 1024 * 1024;
const exporter = "/opt/pauk-remnawave-3411-release/export.py";

export async function normalizeRemnawaveSnapshot(bytes: Uint8Array, signal: AbortSignal) {
  return new Promise<Buffer>((resolve, reject) => {
    const child = spawn("/usr/bin/python3", [exporter, "--normalize"], {
      signal, timeout: 22_000, env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", PYTHONIOENCODING: "utf-8" },
    });
    const chunks: Buffer[] = [];
    let size = 0;
    child.stdout.on("data", (part: Buffer) => {
      size += part.length;
      if (size > maxSnapshotBytes) child.kill();
      else chunks.push(part);
    });
    child.stderr.resume();
    child.stdin.on("error", () => { /* Process exit is handled below. */ });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0 && size > 0 && size <= maxSnapshotBytes) resolve(Buffer.concat(chunks));
      else reject(new Error("invalid complete Remnawave snapshot"));
    });
    child.stdin.end(bytes);
  });
}
