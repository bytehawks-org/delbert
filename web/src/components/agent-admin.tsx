"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";
const groupsOf = (text: string) => text.split(",").map((g) => g.trim()).filter(Boolean);

/** Registers agents and edits their groups. Enrollment itself happens on the host, with an enrollment key. */
export function AgentAdmin({ tenant, agents }: { tenant: string; agents: { name: string; groups: string[] }[] }) {
  const t = useTranslations("agentAdmin");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [groups, setGroups] = useState<Record<string, string>>({});
  const base = `/v1/tenants/${encodeURIComponent(tenant)}/agents`;

  async function run(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown) {
    setError(null);
    const r = await callCore(method, path, body);
    if (!r.ok) return setError(r.error ?? "?");
    router.refresh();
  }

  return (
    <div className="space-y-4">
      <form
        action={async (form) => {
          await run("POST", base, { name: String(form.get("name") ?? "").trim(), groups: groupsOf(String(form.get("groups") ?? "")) });
        }}
        className="flex flex-wrap items-end gap-3 text-sm"
      >
        <label className="flex flex-col gap-1">
          <span className="text-muted">{t("name")}</span>
          <input name="name" required className={`w-44 ${field}`} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-muted">{t("groups")}</span>
          <input name="groups" placeholder="web, db" className={`w-44 ${field}`} />
        </label>
        <button type="submit" className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg">
          {t("add")}
        </button>
      </form>
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("name"), t("groups"), ""]} empty={t("none")}>
        {agents.map((a) => {
          const value = groups[a.name] ?? a.groups.join(", ");
          return (
            <Row key={a.name}>
              <Cell>{a.name}</Cell>
              <Cell>
                <input aria-label={t("groupsOf", { name: a.name })} value={value} onChange={(e) => setGroups({ ...groups, [a.name]: e.target.value })} className={`w-56 ${field}`} />
              </Cell>
              <Cell>
                <div className="flex gap-2">
                  <button type="button" className={button} disabled={value === a.groups.join(", ")} onClick={() => run("PUT", `${base}/${encodeURIComponent(a.name)}`, { groups: groupsOf(value) })}>
                    {t("saveGroups")}
                  </button>
                  <button
                    type="button"
                    className={`${button} text-danger`}
                    onClick={() => {
                      if (window.prompt(t("confirmDelete", { name: a.name })) === a.name) void run("DELETE", `${base}/${encodeURIComponent(a.name)}`);
                    }}
                  >
                    {t("delete")}
                  </button>
                </div>
              </Cell>
            </Row>
          );
        })}
      </Table>
    </div>
  );
}
