import "server-only";

import { randomUUID } from "node:crypto";
import { chmod, readFile, rename, rm, writeFile } from "node:fs/promises";

const announcementPath = "/var/lib/pauk-subscription-announcement/announce.b64";

export async function getSubscriptionAnnouncement(): Promise<string> {
  const value = await readFile(announcementPath, "ascii");
  if (value === "") return "";
  if (!/^base64:[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("Invalid subscription announcement");
  }
  return Buffer.from(value.slice("base64:".length), "base64").toString("utf8");
}

export async function saveSubscriptionAnnouncement(text: string): Promise<void> {
  const header = text ? "base64:" + Buffer.from(text, "utf8").toString("base64") : "";
  const pending = announcementPath + "." + randomUUID();
  await writeFile(pending, header, { flag: "wx", mode: 0o600 });
  try {
    await chmod(pending, 0o644);
    await rename(pending, announcementPath);
  } finally {
    await rm(pending, { force: true });
  }
}
