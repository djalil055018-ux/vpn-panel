import { spawn } from "node:child_process";
import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";

export const runtime = "nodejs";

const maximum = 64 * 1024 * 1024;
let running = false;

function error(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function exportSnapshot(origin: string, token: string, signal: AbortSignal) {
  return new Promise<Uint8Array<ArrayBuffer>>((resolve, reject) => {
    const process = spawn("/usr/bin/python3", ["/opt/pauk-remnawave-3411-release/export.py"], {
      signal, timeout: 65_000, env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", PYTHONIOENCODING: "utf-8" },
    });
    const chunks: Buffer[] = [];
    let outputBytes = 0;
    let stderr = "";
    process.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > maximum) {
        process.kill();
        reject(new Error("Снимок больше 64 МиБ."));
      } else {
        chunks.push(chunk);
      }
    });
    process.stderr.setEncoding("utf8");
    process.stderr.on("data", (part: string) => { stderr = (stderr + part).slice(0, 240); });
    process.stdin.on("error", () => { /* The child exit determines the response. */ });
    process.on("error", reject);
    process.on("close", (code) => {
      if (code === 0 && outputBytes > 0 && outputBytes <= maximum) {
        resolve(Uint8Array.from(Buffer.concat(chunks)));
      } else {
        reject(new Error(stderr.trim() || "Не удалось получить снимок. Проверьте HTTPS и права токена."));
      }
    });
    process.stdin.end(JSON.stringify({ origin, token }));
  });
}

export async function POST(request: NextRequest) {
  if ((await getSession())?.role !== "owner") return error("Действие доступно владельцу PAUK.", 403);
  const canonical = new URL(process.env.VPN_PLATFORM_PUBLIC_URL ?? request.nextUrl.origin).origin;
  if (request.headers.get("origin") !== canonical) return error("Откройте форму в панели PAUK.", 403);
  if (running) return error("Создание снимка уже выполняется.", 409);
  try {
    const size = Number(request.headers.get("content-length"));
    if (!Number.isSafeInteger(size) || size < 1 || size > 12_288) return error("Проверьте адрес и токен.", 400);
    const { source, token } = await request.json();
    if (typeof source !== "string" || source.length > 512 || typeof token !== "string" || !/^[!-~]{1,8192}$/.test(token)) {
      return error("Укажите адрес панели и токен Remnawave.", 400);
    }
    const origin = new URL(source.trim());
    if (origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/" ||
        origin.search || origin.hash || !origin.hostname.includes(".")) {
      return error("Укажите публичный HTTPS-адрес панели без пути.", 400);
    }
    if (running) return error("Создание снимка уже выполняется.", 409);
    running = true;
    try {
      const data = await exportSnapshot(origin.origin, token, request.signal);
      return new NextResponse(data, {
        headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store" },
      });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "";
      return error(message && !/^[A-Z]/.test(message) ? message : "Не удалось получить снимок Remnawave.", 502);
    } finally {
      running = false;
    }
  } catch {
    return error("Проверьте публичный HTTPS-адрес Remnawave и токен.", 400);
  }
}
