"use server";
import { redirect } from "next/navigation";
import { destroySession, loginAdmin } from "@/lib/auth";

export async function loginAction(formData: FormData) {
  const username = String(formData.get("username") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const factor = String(formData.get("factor") ?? "").trim();
  const session = await loginAdmin(username, password, factor);
  if (!session) redirect("/login?error=invalid");
  redirect(session.role === "monitor" ? "/monitor" : "/dashboard");
}
export async function logoutAction() {
  await destroySession();
  redirect("/login");
}
