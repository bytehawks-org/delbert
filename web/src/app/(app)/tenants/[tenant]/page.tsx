import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { AgentsTable } from "@/components/agents-table";
import { Badge, Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

type Props = { params: Promise<{ tenant: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).tenant) };
}

export default async function Tenant({ params }: Props) {
  const tenant = decodeURIComponent((await params).tenant);
  const { token } = await requireMe();
  const t = await getTranslations("tenants");
  const api = core(token);
  const p = { params: { path: { tenant } } };
  const [agents, policies, artifacts, secrets] = await Promise.all([
    api.GET("/v1/tenants/{tenant}/agents", p),
    api.GET("/v1/tenants/{tenant}/policies", p),
    api.GET("/v1/tenants/{tenant}/artifacts", p),
    api.GET("/v1/tenants/{tenant}/secrets", p),
  ]);
  const [a, pol, art, sec] = [unwrap(agents), unwrap(policies), unwrap(artifacts), unwrap(secrets)];
  const denied = <Notice>{t("denied")}</Notice>;

  return (
    <div className="space-y-6">
      <PageHeader title={tenant} back={{ href: "/tenants", label: t("title") }} />
      <Card id="agents" title={t("agents")}>
        {a ? <AgentsTable agents={a.map((x) => ({ ...x, tenant }))} /> : denied}
      </Card>
      <Card id="policies" title={t("policies")}>
        {pol ? (
          <Table caption={t("policies")} head={[t("name"), t("activeVersion"), t("latestVersion")]} empty={t("noPolicies")}>
            {pol.map((x) => (
              <Row key={x.name}>
                <Cell>
                  <Link href={`/tenants/${encodeURIComponent(tenant)}/policies/${encodeURIComponent(x.name)}`} className="font-medium text-accent hover:underline">
                    {x.name}
                  </Link>
                </Cell>
                <Cell>{x.active_version ?? <Badge>{t("inactive")}</Badge>}</Cell>
                <Cell>{x.latest_version ?? "—"}</Cell>
              </Row>
            ))}
          </Table>
        ) : (
          denied
        )}
      </Card>
      <div className="grid gap-6 md:grid-cols-2">
        <Card id="artifacts" title={t("artifacts")}>
          {art ? (
            <Table caption={t("artifacts")} head={[t("name"), t("version"), t("size"), "SHA-256"]} empty={t("noArtifacts")}>
              {art.map((x) => (
                <Row key={x.name}>
                  <Cell>{x.name}</Cell>
                  <Cell>{x.version}</Cell>
                  <Cell>{x.size}</Cell>
                  <Cell mono>{x.sha256.slice(0, 12)}…</Cell>
                </Row>
              ))}
            </Table>
          ) : (
            denied
          )}
        </Card>
        <Card id="secrets" title={t("secrets")}>
          {sec ? (
            <>
              <p className="mb-3 text-xs text-muted">{t("secretsNote")}</p>
              <Table caption={t("secrets")} head={[t("name"), t("updatedBy"), t("updatedAt")]} empty={t("noSecrets")}>
                {sec.map((x) => (
                  <Row key={x.name}>
                    <Cell>{x.name}</Cell>
                    <Cell>{x.updated_by}</Cell>
                    <Cell>{stamp(x.updated_at)}</Cell>
                  </Row>
                ))}
              </Table>
            </>
          ) : (
            denied
          )}
        </Card>
      </div>
    </div>
  );
}
