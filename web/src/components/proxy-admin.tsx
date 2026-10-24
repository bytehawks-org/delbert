"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { callCore } from "@/lib/mutate";

const field = "rounded-md border border-border bg-surface px-2 py-1.5";

/** Registers a branch-office proxy (its one-time enrollment key is shown once) and removes proxies. */
export function ProxyAdmin({ names }: { names: string[] }) {
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

  async function remove(name: string) {
    if (window.prompt(t("confirmDelete", { name })) !== name) return;
    const r = await callCore("DELETE", `/v1/proxies/${encodeURIComponent(name)}`);
    if (!r.ok) return setError(r.error ?? "?");
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
        <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg">
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
      {names.length > 0 && (
        <ul className="flex flex-wrap gap-3 text-sm">
          {names.map((n) => (
            <li key={n} className="flex items-center gap-2 rounded-md border border-border px-2 py-1">
              {n}
              <button type="button" onClick={() => remove(n)} className="text-danger hover:underline" aria-label={t("deleteProxy", { name: n })}>
                {t("delete")}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
