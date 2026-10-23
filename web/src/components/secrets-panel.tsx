"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useRef, useState } from "react";
import { Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

export type SecretRow = { name: string; updated_by: string; updatedLabel: string };

/** Secrets are write-only: the value goes to the Core and is never shown again. */
export function SecretsPanel({ tenant, secrets, canWrite }: { tenant: string; secrets: SecretRow[]; canWrite: boolean }) {
  const t = useTranslations("secrets");
  const router = useRouter();
  const form = useRef<HTMLFormElement>(null);
  const [error, setError] = useState<string | null>(null);
  const base = `/v1/tenants/${encodeURIComponent(tenant)}/secrets`;

  async function save(data: FormData) {
    setError(null);
    const r = await callCore("PUT", `${base}/${encodeURIComponent(String(data.get("name")))}`, { value: String(data.get("value")) });
    if (r.ok) {
      form.current?.reset();
      router.refresh();
    } else setError(r.error ?? "?");
  }

  async function remove(name: string) {
    if (!confirm(t("confirmDelete", { name }))) return;
    const r = await callCore("DELETE", `${base}/${encodeURIComponent(name)}`);
    if (r.ok) router.refresh();
    else setError(r.error ?? "?");
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">{t("note")}</p>
      {canWrite && (
        <form ref={form} action={save} className="flex flex-wrap items-end gap-3 text-sm">
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("name")}</span>
            <input name="name" required pattern="[A-Za-z0-9._-]+" className="w-40 rounded-md border border-border bg-surface px-2 py-1.5" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("value")}</span>
            <input name="value" type="password" required autoComplete="off" className="w-48 rounded-md border border-border bg-surface px-2 py-1.5" />
          </label>
          <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg">
            {t("save")}
          </button>
        </form>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("name"), t("updatedBy"), t("updatedAt"), ""]} empty={t("none")}>
        {secrets.map((s) => (
          <Row key={s.name}>
            <Cell>{s.name}</Cell>
            <Cell>{s.updated_by}</Cell>
            <Cell>{s.updatedLabel}</Cell>
            <Cell>
              {canWrite && (
                <button type="button" onClick={() => remove(s.name)} className="text-danger hover:underline">
                  {t("delete")}
                </button>
              )}
            </Cell>
          </Row>
        ))}
      </Table>
    </div>
  );
}
