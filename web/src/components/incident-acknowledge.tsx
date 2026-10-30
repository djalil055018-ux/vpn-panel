"use client";
import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { acknowledgeIncidentAction } from "@/app/monitoring-actions";
function Submit() { const { pending } = useFormStatus();return <button className="button ghost" disabled={pending}>{pending ? "Сохранение…" : "Проблема замечена"}</button>; }
export function IncidentAcknowledge({ id }: { id: string }) { const [state, action] = useActionState(acknowledgeIncidentAction, { ok: false, message: "" });return <form action={action}><input type="hidden" name="id" value={id} /><Submit />{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}</form>; }
