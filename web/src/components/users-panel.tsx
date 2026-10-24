"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

type Assignment = { role: string; tenant?: string | null };
type User = { username: string; active: boolean; assignments: Assignment[] };
type Role = { name: string; scope: string };

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";

/** Users with their role assignments. The Core refuses anything the signed-in user may not do; the UI only hides controls. */
export function UsersPanel({ users, roles, tenants, me, canWrite }: { users: User[]; roles: Role[]; tenants: string[]; me: string; canWrite: boolean }) {
  const t = useTranslations("users");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState<Assignment[]>([]);

  async function run(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<boolean> {
    setError(null);
    const r = await callCore(method, path, body);
    if (!r.ok) setError(r.error ?? "?");
    else router.refresh();
    return r.ok;
  }

  const label = (a: Assignment) => (a.tenant ? `${a.role} @ ${a.tenant}` : `${a.role} (${t("global")})`);

  async function create(form: FormData) {
    const role = String(form.get("role") ?? "");
    const tenant = String(form.get("tenant") ?? "");
    const ok = await run("POST", "/v1/users", {
      username: String(form.get("username") ?? "").trim(),
      password: String(form.get("password") ?? ""),
      assignments: role ? [{ role, tenant: tenant || null }] : [],
    });
    if (ok) (document.getElementById("new-user") as HTMLFormElement | null)?.reset();
  }

  function addAssignment(form: FormData) {
    const role = String(form.get("role") ?? "");
    const tenant = String(form.get("tenant") ?? "") || null;
    if (role && !draft.some((a) => a.role === role && (a.tenant ?? null) === tenant)) setDraft([...draft, { role, tenant }]);
  }

  async function remove(username: string) {
    if (window.prompt(t("confirmDelete", { name: username })) !== username) return;
    await run("DELETE", `/v1/users/${encodeURIComponent(username)}`);
  }

  const roleOptions = roles.map((r) => (
    <option key={r.name} value={r.name}>
      {r.name}
    </option>
  ));
  const tenantOptions = (
    <>
      <option value="">{t("global")}</option>
      {tenants.map((x) => (
        <option key={x} value={x}>
          {x}
        </option>
      ))}
    </>
  );

  return (
    <div className="space-y-6">
      {canWrite && (
        <form id="new-user" action={create} className="flex flex-wrap items-end gap-3 text-sm">
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("username")}</span>
            <input name="username" required className={`w-40 ${field}`} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("password")}</span>
            <input name="password" type="password" required minLength={12} autoComplete="new-password" className={`w-48 ${field}`} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("role")}</span>
            <select name="role" className={field} defaultValue="">
              <option value="">{t("noRole")}</option>
              {roleOptions}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">{t("scope")}</span>
            <select name="tenant" className={field}>
              {tenantOptions}
            </select>
          </label>
          <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg">
            {t("create")}
          </button>
        </form>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("username"), t("state"), t("assignments"), ""]} empty={t("none")}>
        {users.map((u) => (
          <Row key={u.username}>
            <Cell>{u.username}</Cell>
            <Cell>{u.active ? <Badge tone="ok">{t("active")}</Badge> : <Badge tone="bad">{t("inactive")}</Badge>}</Cell>
            <Cell>
              {editing === u.username ? (
                <div className="space-y-2">
                  <ul className="flex flex-wrap gap-2">
                    {draft.map((a) => (
                      <li key={label(a)} className="flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-xs">
                        {label(a)}
                        <button type="button" aria-label={t("removeAssignment", { what: label(a) })} onClick={() => setDraft(draft.filter((x) => x !== a))}>
                          ×
                        </button>
                      </li>
                    ))}
                  </ul>
                  <form action={addAssignment} className="flex flex-wrap items-center gap-2 text-xs">
                    <select name="role" aria-label={t("role")} className={field}>
                      {roleOptions}
                    </select>
                    <select name="tenant" aria-label={t("scope")} className={field}>
                      {tenantOptions}
                    </select>
                    <button type="submit" className={button}>
                      {t("addAssignment")}
                    </button>
                  </form>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className="rounded-md bg-accent px-2 py-1 text-xs font-medium text-accent-fg"
                      onClick={async () => {
                        if (await run("PUT", `/v1/users/${encodeURIComponent(u.username)}`, { assignments: draft })) setEditing(null);
                      }}
                    >
                      {t("saveAssignments")}
                    </button>
                    <button type="button" className={button} onClick={() => setEditing(null)}>
                      {t("cancel")}
                    </button>
                  </div>
                </div>
              ) : u.assignments.length ? (
                <ul className="flex flex-wrap gap-2">
                  {u.assignments.map((a) => (
                    <li key={label(a)} className="rounded-full border border-border px-2 py-0.5 text-xs">
                      {label(a)}
                    </li>
                  ))}
                </ul>
              ) : (
                "—"
              )}
            </Cell>
            <Cell>
              {canWrite && (
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className={button}
                    onClick={() => {
                      setDraft(u.assignments);
                      setEditing(u.username);
                    }}
                  >
                    {t("editAssignments")}
                  </button>
                  <button type="button" className={button} onClick={() => run("PUT", `/v1/users/${encodeURIComponent(u.username)}`, { active: !u.active })}>
                    {u.active ? t("deactivate") : t("activate")}
                  </button>
                  <button
                    type="button"
                    className={button}
                    onClick={() => {
                      const password = window.prompt(t("newPassword"));
                      if (password) void run("PUT", `/v1/users/${encodeURIComponent(u.username)}`, { password });
                    }}
                  >
                    {t("setPassword")}
                  </button>
                  <button type="button" className={button} onClick={() => run("DELETE", `/v1/users/${encodeURIComponent(u.username)}/mfa`)}>
                    {t("resetMfa")}
                  </button>
                  <button type="button" className={button} onClick={() => run("DELETE", `/v1/users/${encodeURIComponent(u.username)}/sessions`)}>
                    {t("revokeSessions")}
                  </button>
                  {u.username !== me && (
                    <button type="button" className={`${button} text-danger`} onClick={() => remove(u.username)}>
                      {t("delete")}
                    </button>
                  )}
                </div>
              )}
            </Cell>
          </Row>
        ))}
      </Table>
    </div>
  );
}
