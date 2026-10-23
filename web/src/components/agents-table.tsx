import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { stamp } from "@/lib/data";

export type AgentRow = {
  tenant: string;
  name: string;
  groups: string[];
  effective_version: number;
  reported_version?: number | null;
  compliant?: boolean | null;
  reported_at?: number | null;
  proxy?: string | null;
};

export async function AgentsTable({ agents, showTenant = false }: { agents: AgentRow[]; showTenant?: boolean }) {
  const t = await getTranslations("agents");
  return (
    <Table
      caption={t("title")}
      head={[...(showTenant ? [t("tenant")] : []), t("name"), t("state"), t("groups"), t("version"), t("proxy"), t("reportedAt")]}
      empty={t("none")}
    >
      {agents.map((a) => (
        <Row key={`${a.tenant}/${a.name}`}>
          {showTenant && (
            <Cell>
              <Link href={`/tenants/${encodeURIComponent(a.tenant)}`} className="hover:underline">
                {a.tenant}
              </Link>
            </Cell>
          )}
          <Cell>
            <Link href={`/tenants/${encodeURIComponent(a.tenant)}/agents/${encodeURIComponent(a.name)}`} className="font-medium text-accent hover:underline">
              {a.name}
            </Link>
          </Cell>
          <Cell>
            {a.compliant == null ? <Badge>{t("unknown")}</Badge> : a.compliant ? <Badge tone="ok">{t("compliant")}</Badge> : <Badge tone="bad">{t("drifted")}</Badge>}
          </Cell>
          <Cell>{a.groups.join(", ") || "—"}</Cell>
          <Cell>
            {a.effective_version}
            {a.reported_version != null && a.reported_version !== a.effective_version ? <span className="text-muted"> ({t("applied", { version: a.reported_version })})</span> : null}
          </Cell>
          <Cell>{a.proxy ?? "—"}</Cell>
          <Cell>{stamp(a.reported_at)}</Cell>
        </Row>
      ))}
    </Table>
  );
}
