export type AutoProfileSettings = { tenant_id: string; enabled: boolean; name: string; russia_direct: boolean; xray_network_policy: "tunnel" | "split_dns" };
export function autoProfileInput(form: FormData): Omit<AutoProfileSettings, "tenant_id"> | null {
  const name = String(form.get("name") ?? "").trim();
  if (!name || Array.from(name).length > 80 || /[\u0000-\u001f\u007f]/.test(name)) return null;
  const policy = String(form.get("xray_network_policy") ?? "tunnel");
  if (policy !== "tunnel" && policy !== "split_dns") return null;
  return { name, enabled: form.get("enabled") === "on", russia_direct: form.get("russia_direct") === "on", xray_network_policy: policy };
}
