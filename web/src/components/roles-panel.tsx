"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useMemo, useState } from "react";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

type Role = { name: string; permissions: string[]; builtin: boolean; scope: string };
type Catalog = { permission: string; global_only: boolean }[];

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";

/** Roles and the permission matrix (resources by actions). Built-in roles are read-only; custom roles are edited here. */
export function RolesPanel({ roles, catalog, canWrite }: { roles: Role[]; catalog: Catalog; canWrite: boolean }) {
  const t = useTranslations("roles");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("tenant");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<string | null>(null); // name of the custom role being edited

  // Matrix axes in catalog order: one row per resource, one column per action.
  const { resources, actions } = useMemo(() => {
    const resources: string[] = [];
    const actions: string[] = [];
    for (const { permission } of catalog) {
      const [res = "", act = ""] = permission.split(":");
      if (!resources.includes(res)) resources.push(res);
      if (!actions.includes(act)) actions.push(act);
    }
    return { resources, actions };
  }, [catalog]);
  const known = new Map(catalog.map((c) => [c.permission, c.global_only]));

  const wildcard = picked.has("*");
  const has = (res: string, act: string) => wildcard || picked.has(`${res}:*`) || picked.has(`${res}:${act}`);
  const blocked = (res: string, act: string) => scope === "tenant" && known.get(`${res}:${act}`) === true;

  function toggle(permission: string) {
    const next = new Set(picked);
    if (!next.delete(permission)) next.add(permission);
    setPicked(next);
  }

  /** `resource:*` replaces the individual cells of its row; unticking it clears the row. */
  function toggleRow(res: string) {
    const next = new Set([...picked].filter((p) => !p.startsWith(`${res}:`)));
    if (!picked.has(`${res}:*`)) next.add(`${res}:*`);
    setPicked(next);
  }

  function edit(role: Role) {
    setEditing(role.name);
    setName(role.name);
    setScope(role.scope);
    setPicked(new Set(role.permissions));
    setError(null);
  }

  function reset() {
    setEditing(null);
    setName("");
    setScope("tenant");
    setPicked(new Set());
  }

  async function save() {
    setError(null);
    const permissions = [...picked].sort();
    const r = editing
      ? await callCore("PUT", `/v1/roles/${encodeURIComponent(editing)}`, { name, scope, permissions })
      : await callCore("POST", "/v1/roles", { name: name.trim(), scope, permissions });
    if (!r.ok) return setError(r.error ?? "?");
    reset();
    router.refresh();
  }

  async function remove(role: string) {
    if (window.prompt(t("confirmDelete", { name: role })) !== role) return;
    const r = await callCore("DELETE", `/v1/roles/${encodeURIComponent(role)}`);
    if (!r.ok) return setError(r.error ?? "?");
    if (editing === role) reset();
    router.refresh();
  }

  return (
    <div className="space-y-6">
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("name"), t("scope"), t("permissions"), ""]} empty={t("none")}>
        {roles.map((r) => (
          <Row key={r.name}>
            <Cell>
              {r.name} {r.builtin && <Badge>{t("builtin")}</Badge>}
            </Cell>
            <Cell>{t(`scopes.${r.scope}` as "scopes.any")}</Cell>
            <Cell>
              <ul className="flex flex-wrap gap-1">
                {r.permissions.map((p) => (
                  <li key={p} className="rounded border border-border px-1.5 py-0.5 font-mono text-xs">
                    {p}
                  </li>
                ))}
              </ul>
            </Cell>
            <Cell>
              {canWrite && !r.builtin && (
                <div className="flex gap-2">
                  <button type="button" className={button} onClick={() => edit(r)}>
                    {t("edit")}
                  </button>
                  <button type="button" className={`${button} text-danger`} onClick={() => remove(r.name)}>
                    {t("delete")}
                  </button>
                </div>
              )}
            </Cell>
          </Row>
        ))}
      </Table>

      {canWrite && (
        <section aria-labelledby="matrix" className="space-y-3 rounded-lg border border-border bg-surface p-5">
          <h2 id="matrix" className="text-lg font-medium">
            {editing ? t("editing", { name: editing }) : t("newRole")}
          </h2>
          <div className="flex flex-wrap items-end gap-3 text-sm">
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("name")}</span>
              <input value={name} onChange={(e) => setName(e.target.value)} disabled={!!editing} className={`w-44 ${field}`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("scope")}</span>
              <select value={scope} onChange={(e) => setScope(e.target.value)} className={field}>
                {["tenant", "global", "any"].map((s) => (
                  <option key={s} value={s}>
                    {t(`scopes.${s}` as "scopes.any")}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p className="text-xs text-muted">{t("matrixHelp")}</p>
          <div className="overflow-x-auto">
            <table className="text-left text-sm">
              <caption className="sr-only">{t("matrix")}</caption>
              <thead>
                <tr className="border-b border-border text-muted">
                  <th scope="col" className="py-2 pr-4 font-medium">
                    {t("resource")}
                  </th>
                  {actions.map((a) => (
                    <th key={a} scope="col" className="px-3 py-2 font-medium">
                      {a}
                    </th>
                  ))}
                  <th scope="col" className="px-3 py-2 font-medium">
                    {t("all")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {resources.map((res) => (
                  <tr key={res} className="border-b border-border last:border-0">
                    <th scope="row" className="py-2 pr-4 font-mono text-xs font-normal">
                      {res}
                    </th>
                    {actions.map((act) => {
                      const exists = known.has(`${res}:${act}`);
                      return (
                        <td key={act} className="px-3 py-2 text-center">
                          {exists && (
                            <input
                              type="checkbox"
                              aria-label={`${res}:${act}`}
                              checked={has(res, act)}
                              disabled={wildcard || picked.has(`${res}:*`) || blocked(res, act)}
                              onChange={() => toggle(`${res}:${act}`)}
                            />
                          )}
                        </td>
                      );
                    })}
                    <td className="px-3 py-2 text-center">
                      <input type="checkbox" aria-label={`${res}:*`} checked={wildcard || picked.has(`${res}:*`)} disabled={wildcard || (scope === "tenant" && actions.every((a) => !known.has(`${res}:${a}`) || blocked(res, a)))} onChange={() => toggleRow(res)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={save} disabled={!name.trim() || picked.size === 0} className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg disabled:opacity-50">
              {t("save")}
            </button>
            {editing && (
              <button type="button" onClick={reset} className={button}>
                {t("cancel")}
              </button>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
