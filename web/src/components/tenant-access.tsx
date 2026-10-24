"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

type Assignment = { username: string; role: string };

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";

/** Who holds which role in this tenant, and the tenant's approval setting. The Core limits what a delegated administrator can grant. */
export function TenantAccess({
  tenant,
  assignments,
  roles,
  approvalRequired,
  canAssign,
  canSettings,
}: {
  tenant: string;
  assignments: Assignment[];
  roles: string[]; // roles that may be assigned inside a tenant
  approvalRequired: boolean | null; // null: the settings are not visible to this user
  canAssign: boolean;
  canSettings: boolean;
}) {
  const t = useTranslations("access");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [approval, setApprovalState] = useState(approvalRequired);
  const [editing, setEditing] = useState<string | null>(null); // "" while adding a new user
  const [user, setUser] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const base = `/v1/tenants/${encodeURIComponent(tenant)}`;

  const byUser = new Map<string, string[]>();
  for (const a of assignments) byUser.set(a.username, [...(byUser.get(a.username) ?? []), a.role]);

  async function save(username: string, chosen: string[]) {
    setError(null);
    const r = await callCore("PUT", `${base}/assignments/${encodeURIComponent(username)}`, { roles: chosen });
    if (!r.ok) return setError(r.error ?? "?");
    setEditing(null);
    router.refresh();
  }

  async function setApproval(value: boolean) {
    setError(null);
    setApprovalState(value); // optimistic; rolled back if the Core refuses
    const r = await callCore("PUT", `${base}/settings`, { approval_required: value });
    if (!r.ok) {
      setApprovalState(!value);
      return setError(r.error ?? "?");
    }
    router.refresh();
  }

  function start(username: string, current: string[]) {
    setEditing(username);
    setUser(username);
    setPicked(new Set(current));
  }

  const editor = (
    <div className="space-y-2 text-sm">
      {editing === "" && (
        <label className="flex flex-col gap-1">
          <span className="text-muted">{t("username")}</span>
          <input value={user} onChange={(e) => setUser(e.target.value)} className={`w-48 ${field}`} />
        </label>
      )}
      <fieldset className="flex flex-wrap gap-x-4 gap-y-1">
        <legend className="sr-only">{t("roles")}</legend>
        {roles.map((r) => (
          <label key={r} className="flex items-center gap-1">
            <input
              type="checkbox"
              checked={picked.has(r)}
              onChange={() => {
                const next = new Set(picked);
                if (!next.delete(r)) next.add(r);
                setPicked(next);
              }}
            />
            {r}
          </label>
        ))}
      </fieldset>
      <div className="flex gap-2">
        <button type="button" disabled={!user.trim()} className="rounded-md bg-accent px-2 py-1 text-xs font-medium text-accent-fg disabled:opacity-50" onClick={() => save(user.trim(), [...picked])}>
          {t("save")}
        </button>
        <button type="button" className={button} onClick={() => setEditing(null)}>
          {t("cancel")}
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {approval !== null && (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={approval} disabled={!canSettings} onChange={(e) => setApproval(e.target.checked)} />
          <span>{t("approval")}</span>
          <span className="text-muted">— {t("approvalHelp")}</span>
        </label>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("username"), t("roles"), ""]} empty={t("none")}>
        {[...byUser].map(([name, held]) => (
          <Row key={name}>
            <Cell>{name}</Cell>
            <Cell>
              {editing === name ? (
                editor
              ) : (
                <ul className="flex flex-wrap gap-1">
                  {held.map((r) => (
                    <li key={r}>
                      <Badge>{r}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </Cell>
            <Cell>
              {canAssign && editing !== name && (
                <div className="flex gap-2">
                  <button type="button" className={button} onClick={() => start(name, held)}>
                    {t("edit")}
                  </button>
                  <button
                    type="button"
                    className={`${button} text-danger`}
                    onClick={() => {
                      if (window.confirm(t("confirmRemove", { name }))) void save(name, []);
                    }}
                  >
                    {t("remove")}
                  </button>
                </div>
              )}
            </Cell>
          </Row>
        ))}
      </Table>
      {canAssign &&
        (editing === "" ? (
          editor
        ) : (
          <button type="button" className={button} onClick={() => start("", [])}>
            {t("add")}
          </button>
        ))}
    </div>
  );
}
