"use client";
import { useState } from "react";
import { ProtocolTemplateApply } from "@/components/protocol-template-apply";
import type { ProtocolTemplateCatalog } from "@/lib/protocol-templates";
export function ProtocolTemplateLibrary({ catalog, canApply=false, initialTemplate="", initialInstallation="" }: { catalog: ProtocolTemplateCatalog; canApply?:boolean; initialTemplate?:string; initialInstallation?:string }) {
  const [selected, setSelected] = useState(catalog.templates.some(t=>t.id===initialTemplate)?initialTemplate:catalog.templates[0].id);
  const [filter, setFilter] = useState("all");
  const [role, setRole] = useState("client");
  const [message, setMessage] = useState("");
  const template = catalog.templates.find(t => t.id === selected) ?? catalog.templates[0];
  const file = template.files.find(f => f.role === role) ?? template.files[0];
  const families = [...new Set(catalog.templates.map(t => t.family))];
  const visible = catalog.templates.filter(t => filter === "all" || (filter === "recommended" ? t.recommended : t.family === filter));
  async function copy() {
    if (!file) return;
    try { await navigator.clipboard.writeText(file.content); setMessage("Пример скопирован. Заполните параметры своей установки."); }
    catch { setMessage("Браузер не разрешил копирование. Скачайте файл или выделите текст примера."); }
  }
  function download() {
    if (!file) return;
    const url = URL.createObjectURL(new Blob([file.content], { type: "text/plain;charset=utf-8" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = template.id + "-" + file.name; anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setMessage("Файл скачан. Перед запуском заполните параметры и создайте собственные ключи.");
  }
  return <div className="template-library">
    <section className="panel template-notice"><h2>Добавить отдельный сервис на сервер</h2><p>Выберите шаблон и сервер, проверьте параметры и нажмите «Применить». Ключи и настройки будут подготовлены панелью и агентом. В шаблонах нет квот трафика и ограничителей скорости.</p><p>Универсально самого быстрого протокола нет. Проверяйте подключение и передачу данных через своего оператора: недоступный IP нельзя исправить выбором шаблона.</p></section>
    <div className="template-toolbar"><label>Показать <select value={filter} onChange={e => setFilter(e.target.value)}><option value="all">Все варианты</option><option value="recommended">Рекомендуемые</option>{families.map(f => <option key={f} value={f}>{f}</option>)}</select></label><span>Версия {catalog.version} · Проверено {catalog.reviewed_at}</span></div>
    <div className="template-columns"><div className="template-list" aria-label="Варианты протоколов">{visible.map(t => <button type="button" key={t.id} className={"template-card" + (selected === t.id ? " selected" : "")} aria-pressed={selected === t.id} onClick={() => { if(selected!==t.id) window.history.replaceState(null,"","/protocol-templates?template="+encodeURIComponent(t.id)); setSelected(t.id); setMessage(""); if (window.matchMedia("(max-width: 1000px)").matches) requestAnimationFrame(() => document.getElementById("selected-protocol-template")?.scrollIntoView({ block: "start", behavior: "auto" })); }}><strong>{t.name}</strong><span>{t.summary}</span><small>{t.legacy ? "Устаревший · справка" : t.recommended ? "Рекомендуемый вариант" : "Вариант совместимости"}</small></button>)}</div>
    <section id="selected-protocol-template" className="panel template-detail" aria-label="Выбранный шаблон"><h2>{template.name}</h2><p>{template.summary}</p><dl className="template-facts"><div><dt>Транспорт</dt><dd>{template.transport}</dd></div><div><dt>Защита</dt><dd>{template.security}</dd></div><div><dt>Квота в шаблоне</dt><dd>Без ограничения</dd></div><div><dt>Ограничение скорости</dt><dd>Отсутствует</dd></div></dl><p>{template.latency_note}</p><ul>{template.notes.map(note => <li key={note}>{note}</li>)}</ul>
    {canApply&&!template.legacy?<ProtocolTemplateApply key={template.id} template={template} initialInstallation={template.id===initialTemplate?initialInstallation:""}/>:!template.legacy&&<p>Применение шаблонов доступно владельцу панели.</p>}
    {file ? <details className="template-examples"><summary>Примеры конфигураций для ручной настройки</summary><div className="template-file-actions"><label>Пример <select value={role} onChange={e => { setRole(e.target.value); setMessage(""); }}><option value="client">Клиент</option><option value="server">Сервер</option></select></label><button type="button" className="button" onClick={copy}>Копировать</button><button type="button" className="button" onClick={download}>Скачать файл</button></div><p className="template-help">Это пример конфигурации. Замените все значения в двойных фигурных скобках, используйте свои ключи и сертификаты. Выбор карточки сохраняет действующие подключения.</p><details><summary>Параметры для заполнения ({template.placeholders.length})</summary><ul>{template.placeholders.map(p => <li key={p}><code>{"{{" + p + "}}"}</code></li>)}</ul></details><pre className="template-code" tabIndex={0}><code>{file.content}</code></pre><p className="template-hash">SHA-256 файла: <code>{file.sha256}</code></p></details> : <p className="template-help">Для этого устаревшего протокола защищённый шаблон не выдаётся. Выберите современный вариант в списке.</p>}
    <p role="status" aria-live="polite">{message}</p><details><summary>Источники GitHub и закреплённые версии</summary>{catalog.sources.filter(s => template.sources.includes(s.id)).map(s => <div className="template-source" key={s.id}><a href={s.url} target="_blank" rel="noreferrer">{s.repository} / {s.path}</a><p>Commit: <code>{s.ref}</code></p><p>SHA-256 исходника: <code>{s.sha256}</code></p></div>)}<p>Примеры адаптированы для библиотеки PAUK. Исходники закреплены за конкретными коммитами.</p></details></section></div>
  </div>;
}
