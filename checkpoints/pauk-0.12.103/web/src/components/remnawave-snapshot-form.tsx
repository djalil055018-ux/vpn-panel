"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import type { RemnawaveImport } from "@/lib/remnawave-types";
import { remnawaveStatusLabels } from "@/lib/remnawave-types";

type Owner = { id: string; name: string };
type Report = RemnawaveImport["report"];

export function RemnawaveSnapshotForm({ owners }: { owners: Owner[] }) {
  const router = useRouter();
  const [tenant, setTenant] = useState(owners[0]?.id ?? "");
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [result, setResult] = useState<{ id: string; created: boolean } | null>(null);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function capture(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const form = event.currentTarget;
    const credentials = new FormData(form);
    setPending(true);
    setError("");
    try {
      const response = await fetch("/migrations/remnawave/capture", {
        method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: credentials.get("source"), token: credentials.get("token") }),
      });
      if (!response.ok) {
        const failure = await response.json();
        setError(failure.error ?? "Не удалось создать снимок.");
        return;
      }
      setFile(new File([await response.blob()], "remnawave-inventory.json", { type: "application/json" }));
      setReport(null);
      setResult(null);
      form.reset();
    } catch {
      setError("Не удалось получить снимок. Проверьте связь с исходной панелью.");
    } finally {
      setPending(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || !tenant || pending) return;
    if (file.size === 0 || file.size > 64 * 1024 * 1024) {
      setError("Выберите непустой снимок размером до 64 МиБ.");
      return;
    }
    const operation = report ? "stage" : "preview";
    setPending(true);
    setError("");
    try {
      const response = await fetch("/migrations/remnawave/snapshot?" + new URLSearchParams({ operation, tenant }), {
        method: "POST", body: file, cache: "no-store",
        headers: { "Content-Type": "application/json", ...(report && { "X-Reviewed-Inventory-SHA256": report.sha256 }) },
      });
      const value = await response.json();
      if (!response.ok) {
        setError(value.error ?? "Панель не смогла обработать снимок.");
        return;
      }
      if (operation === "preview") {
        setReport(value.report);
      } else {
        setResult({ id: value.import.id, created: value.created });
        router.refresh();
      }
    } catch {
      setError("Не удалось получить результат. Проверьте список снимков перед повтором.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <details>
        <summary>Получить снимок по API Remnawave</summary>
        <form onSubmit={capture} className="portal-form branding-form">
          <label>Адрес панели Remnawave
            <input name="source" type="url" placeholder="https://remnawave.example.com" required maxLength={512} disabled={pending} />
          </label>
          <label>API-токен Remnawave
            <input name="token" type="password" autoComplete="off" required maxLength={8192} disabled={pending} />
          </label>
          <p className="plan-muted">Нужен токен с доступом на чтение клиентов, устройств и конфигурации.</p>
          <button className="button ghost" disabled={pending}>Получить снимок</button>
        </form>
      </details>
      <form onSubmit={submit} className="portal-form branding-form">
      <label>Владелец в PAUK
        <select value={tenant} disabled={pending} onChange={(event) => {
          setTenant(event.target.value); setReport(null); setResult(null); setError("");
        }}>
          {owners.map((owner) => <option key={owner.id} value={owner.id}>{owner.name}</option>)}
        </select>
      </label>
      <label>JSON-снимок Remnawave
        <input type="file" accept=".json,application/json" disabled={pending} onChange={(event) => {
          setFile(event.target.files?.[0] ?? null); setReport(null); setResult(null); setError("");
        }} />
      </label>
      {file && <p>Выбран снимок {file.name}.</p>}\n      {report && (
        <div>
          <p><strong>{report.users}</strong> клиентов · <strong>{report.devices}</strong> устройств · {report.source_origin}</p>
          <p>{Object.entries(report.status_counts).map(([status, count]) => (remnawaveStatusLabels[status] ?? status) + " " + count).join(" · ")}</p>
          <p className="plan-muted">Импорт сохранит клиентов в PAUK с их исходными ключами и сроками. Доступ включается отдельно.</p>
        </div>
      )}
      {error && <p role="alert" className="plan-feedback error">{error}</p>}
      {result ? (
        <p role="status" className="plan-feedback">
          {result.created ? "Снимок импортирован. " : "Этот снимок уже импортирован. "}
          <a href={"/migrations/remnawave/" + result.id}>Открыть клиентов</a>
        </p>
      ) : (
        <button className="button primary" disabled={!file || !tenant || pending}>
          {pending ? "Выполняется…" : report ? "Импортировать клиентов" : "Проверить снимок"}
        </button>
      )}
      </form>
    </>
  );
}
