"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { callCore } from "@/lib/mutate";

/** Creates a tenant (needs `tenants:create`); the Core checks names and permission. */
export function TenantCreate() {
  const t = useTranslations("tenants");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  async function create(form: FormData) {
    setError(null);
    const name = String(form.get("name") ?? "").trim();
    const r = await callCore("POST", "/v1/tenants", { name });
    if (!r.ok) return setError(r.error ?? "?");
    router.push(`/tenants/${encodeURIComponent(name)}`);
    router.refresh();
  }

  return (
    <div className="mb-6 space-y-2">
      <form action={create} className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          <span className="text-muted">{t("newTenant")}</span>
          <input name="name" required pattern="[A-Za-z0-9._\-]{1,128}" className="w-56 rounded-md border border-border bg-surface px-2 py-1.5" />
        </label>
        <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg">
          {t("create")}
        </button>
      </form>
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
