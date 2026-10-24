"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useRef, useState } from "react";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

export type VariableRow = { scope: string; target: string; name: string; value: unknown; locked: boolean; updated_by: string };

const field = "rounded-md border border-border bg-surface px-2 py-1.5";

/** Text that is valid JSON (a number, true, a list…) is stored as that; anything else as text. */
function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * Template variables. Without `tenant` it manages the platform's (global) layer; with one it
 * manages the tenant, group and agent layers and lists the inherited global ones read-only.
 */
export function VariablesPanel({ tenant, variables, canWrite }: { tenant?: string; variables: VariableRow[]; canWrite: boolean }) {
  const t = useTranslations("variables");
  const router = useRouter();
  const form = useRef<HTMLFormElement>(null);
  const [scope, setScope] = useState("tenant");
  const [error, setError] = useState<string | null>(null);
  const base = tenant ? `/v1/tenants/${encodeURIComponent(tenant)}/variables` : "/v1/globals/variables";
  const url = (name: string, s: string, target: string) => `${base}/${encodeURIComponent(name)}${tenant && s !== "tenant" ? `?scope=${s}&target=${encodeURIComponent(target)}` : ""}`;

  async function save(data: FormData) {
    setError(null);
    const s = tenant ? scope : "global";
    const r = await callCore("PUT", url(String(data.get("name")), s, String(data.get("target") ?? "")), { value: parse(String(data.get("value"))), locked: data.get("locked") === "on" });
    if (r.ok) {
      form.current?.reset();
      router.refresh();
    } else setError(r.error ?? "?");
  }

  async function remove(v: VariableRow) {
    if (!confirm(t("confirmDelete", { name: v.name }))) return;
    const r = await callCore("DELETE", url(v.name, v.scope, v.target));
    if (r.ok) router.refresh();
    else setError(r.error ?? "?");
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">{t(tenant ? "noteTenant" : "noteGlobal")}</p>
      {canWrite && (
        <form ref={form} action={save} className="flex flex-wrap items-end gap-3 text-sm">
          {tenant && (
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("scope")}</span>
              <select value={scope} onChange={(e) => setScope(e.target.value)} className={field}>
                <option value="tenant">{t("scopes.tenant")}</option>
                <option value="group">{t("scopes.group")}</option>
                <option value="agent">{t("scopes.agent")}</option>
              </select>
            </label>
          )}
          {tenant && scope !== "tenant" && (
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t(scope === "group" ? "group" : "agent")}</span>
              <input name="target" required pattern="[A-Za-z0-9._-]+" className={`w-36 ${field}`} />
            </label>
          )}
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("name")}</span>
            <input name="name" required pattern="[A-Za-z_][A-Za-z0-9_]*" className={`w-40 ${field}`} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("value")}</span>
            <input name="value" required autoComplete="off" className={`w-48 ${field}`} />
          </label>
          <label className="flex items-center gap-2 pb-2">
            <input name="locked" type="checkbox" />
            <span>{t("constant")}</span>
          </label>
          <button type="submit" className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg">
            {t("save")}
          </button>
        </form>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("scope"), t("name"), t("value"), t("kind"), t("updatedBy"), ""]} empty={t("none")}>
        {variables.map((v) => (
          <Row key={`${v.scope}/${v.target}/${v.name}`}>
            <Cell>{v.target ? `${t(`scopes.${v.scope}`)}: ${v.target}` : t(`scopes.${v.scope}`)}</Cell>
            <Cell mono>{v.name}</Cell>
            <Cell mono>{typeof v.value === "string" ? v.value : JSON.stringify(v.value)}</Cell>
            <Cell>{v.locked ? <Badge tone="ok">{t("constant")}</Badge> : <Badge>{t("variable")}</Badge>}</Cell>
            <Cell>{v.updated_by}</Cell>
            <Cell>
              {canWrite && (!tenant || v.scope !== "global") && (
                <button type="button" onClick={() => remove(v)} className="text-danger hover:underline" aria-label={t("deleteVariable", { name: v.name })}>
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
