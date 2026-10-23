import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { Cell, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("tenants"))("title") };
}

export default async function Tenants() {
  const { token } = await requireMe();
  const t = await getTranslations("tenants");
  const api = core(token);
  const tenants = unwrap(await api.GET("/v1/tenants")) ?? [];
  const rows = await Promise.all(
    tenants.map(async (x) => {
      const params = { params: { path: { tenant: x.name } } };
      const [agents, policies] = await Promise.all([api.GET("/v1/tenants/{tenant}/agents", params), api.GET("/v1/tenants/{tenant}/policies", params)]);
      return { ...x, agents: unwrap(agents)?.length ?? 0, policies: unwrap(policies)?.length ?? 0 };
    }),
  );
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      <Table caption={t("title")} head={[t("name"), t("agents"), t("policies")]} empty={t("none")}>
        {rows.map((x) => (
          <Row key={x.id}>
            <Cell>
              <Link href={`/tenants/${encodeURIComponent(x.name)}`} className="font-medium text-accent hover:underline">
                {x.name}
              </Link>
            </Cell>
            <Cell>{x.agents}</Cell>
            <Cell>{x.policies}</Cell>
          </Row>
        ))}
      </Table>
    </>
  );
}
