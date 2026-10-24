"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { callCore } from "@/lib/mutate";

const field = "rounded-md border border-border bg-surface px-2 py-1.5";

/** Registers a branch-office proxy; its one-time enrollment key is shown once. Per-row actions: `ProxyActions`. */
export function ProxyAdmin() {
  const t = useTranslations("proxies");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ name: string; key: string } | null>(null);

  async function create(form: FormData) {
    setError(null);
    setCreated(null);
    const name = String(form.get("name") ?? "").trim();
    const dns_names = String(form.get("dns") ?? "").split(",").map((d) => d.trim()).filter(Boolean);
    const r = await callCore<{ key: string }>("POST", "/v1/proxies", { name, dns_names });
    if (!r.ok || !r.data) return setError(r.error ?? "?");
    setCreated({ name, key: r.data.key });
    router.refresh();
  }

  return (
    <div className="mb-6 space-y-4">
      <form action={create} className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          <span className="text-muted">{t("name")}</span>
          <input name="name" required className={`w-44 ${field}`} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-muted">{t("dnsNames")}</span>
          <input name="dns" required placeholder="proxy.branch.example.com" className={`w-72 ${field}`} />
        </label>
        <button type="submit" className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg">
          {t("create")}
        </button>
      </form>
      {created && (
        <div role="status" className="rounded-md border border-ok p-3 text-sm">
          <p className="mb-1 font-medium">{t("keyOnce", { name: created.name })}</p>
          <code className="break-all font-mono text-xs" data-testid="proxy-key">
            {created.key}
          </code>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
    </div>
  );
}

export type ProxyRow = { name: string; dns_names: string[]; enrolled: boolean; agents: number; last_seen?: number | null };

/** Row actions: configuration and delete side by side, so neither has to be looked for. */
export function ProxyActions({ proxy, canWrite, seen }: { proxy: ProxyRow; canWrite: boolean; seen: string }) {
  const t = useTranslations("proxies");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function remove() {
    if (window.prompt(t("confirmDelete", { name: proxy.name })) !== proxy.name) return;
    const r = await callCore("DELETE", `/v1/proxies/${encodeURIComponent(proxy.name)}`);
    if (!r.ok) return setError(r.error ?? "?");
    router.refresh();
  }

  const id = `proxy-config-${proxy.name}`;
  return (
    <div className="text-sm">
      <div className="flex gap-3">
        <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} aria-controls={id} aria-label={t("configProxy", { name: proxy.name })} className="hover:underline">
          {t("config")}
        </button>
        {canWrite && (
          <button type="button" onClick={remove} className="text-danger hover:underline" aria-label={t("deleteProxy", { name: proxy.name })}>
            {t("delete")}
          </button>
        )}
      </div>
      {open && (
        <dl id={id} className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-md border border-border bg-surface p-3">
          <dt className="text-muted">{t("name")}</dt>
          <dd>{proxy.name}</dd>
          <dt className="text-muted">{t("state")}</dt>
          <dd>{proxy.enrolled ? t("enrolled") : t("pending")}</dd>
          <dt className="text-muted">{t("dns")}</dt>
          <dd>{proxy.dns_names.join(", ") || "—"}</dd>
          <dt className="text-muted">{t("agents")}</dt>
          <dd>{proxy.agents}</dd>
          <dt className="text-muted">{t("lastSeen")}</dt>
          <dd>{seen}</dd>
        </dl>
      )}
      {error && (
        <p role="alert" className="mt-1 text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
