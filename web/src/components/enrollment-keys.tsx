"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

export type KeyRow = { id: string; uses: number; max_uses: number; expires_at: number; revoked: boolean; groups: string[]; expired: boolean; expiresLabel: string };

export function EnrollmentKeys({ tenant, keys, canWrite }: { tenant: string; keys: KeyRow[]; canWrite: boolean }) {
  const t = useTranslations("keys");
  const router = useRouter();
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const base = `/v1/tenants/${encodeURIComponent(tenant)}/enrollment-keys`;

  async function create(form: FormData) {
    setError(null);
    const groups = String(form.get("groups") ?? "").split(",").map((g) => g.trim()).filter(Boolean);
    const r = await callCore<{ key: string }>("POST", base, { groups, max_uses: Number(form.get("max_uses")) || 1, ttl_hours: Number(form.get("ttl_hours")) || 24 });
    if (r.ok && r.data) {
      setCreated(r.data.key);
      router.refresh();
    } else setError(r.error ?? "?");
  }

  async function revoke(id: string) {
    const r = await callCore("DELETE", `${base}/${encodeURIComponent(id)}`);
    if (r.ok) router.refresh();
    else setError(r.error ?? "?");
  }

  return (
    <div className="space-y-4">
      {canWrite && (
        <form action={create} className="flex flex-wrap items-end gap-3 text-sm">
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("groups")}</span>
            <input name="groups" placeholder="web, db" className="w-44 rounded-md border border-border bg-surface px-2 py-1.5" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("maxUses")}</span>
            <input name="max_uses" type="number" min={1} defaultValue={1} className="w-24 rounded-md border border-border bg-surface px-2 py-1.5" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("ttl")}</span>
            <input name="ttl_hours" type="number" min={1} max={720} defaultValue={24} className="w-24 rounded-md border border-border bg-surface px-2 py-1.5" />
          </label>
          <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg">
            {t("create")}
          </button>
        </form>
      )}
      {created && (
        <div role="status" className="rounded-md border border-ok p-3 text-sm">
          <p className="mb-1 font-medium">{t("shownOnce")}</p>
          <code className="break-all font-mono text-xs" data-testid="new-key">
            {created}
          </code>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("groups"), t("uses"), t("expires"), t("state"), ""]} empty={t("none")}>
        {keys.map((k) => (
          <Row key={k.id}>
            <Cell>{k.groups.join(", ") || "—"}</Cell>
            <Cell>
              {k.uses}/{k.max_uses}
            </Cell>
            <Cell>{k.expiresLabel}</Cell>
            <Cell>{k.revoked ? <Badge tone="bad">{t("revoked")}</Badge> : k.expired ? <Badge>{t("expired")}</Badge> : k.uses >= k.max_uses ? <Badge>{t("used")}</Badge> : <Badge tone="ok">{t("valid")}</Badge>}</Cell>
            <Cell>
              {canWrite && !k.revoked && (
                <button type="button" onClick={() => revoke(k.id)} className="text-danger hover:underline">
                  {t("revoke")}
                </button>
              )}
            </Cell>
          </Row>
        ))}
      </Table>
    </div>
  );
}
