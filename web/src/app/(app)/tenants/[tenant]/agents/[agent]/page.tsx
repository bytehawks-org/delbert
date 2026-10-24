import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { Badge, Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { notFound } from "next/navigation";

type Props = { params: Promise<{ tenant: string; agent: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).agent) };
}

export default async function Agent({ params }: Props) {
  const raw = await params;
  const tenant = decodeURIComponent(raw.tenant);
  const name = decodeURIComponent(raw.agent);
  const { token } = await requireMe();
  const t = await getTranslations("agents");
  const list = unwrap(await core(token).GET("/v1/tenants/{tenant}/agents", { params: { path: { tenant } } })) ?? [];
  const agent = list.find((a) => a.name === name);
  if (!agent) notFound();
  const tVars = await getTranslations("variables");
  const p = { params: { path: { tenant, agent: name } } };
  const resolved = unwrap(await core(token).GET("/v1/tenants/{tenant}/agents/{agent}/variables", p));
  const preview = unwrap(await core(token).GET("/v1/tenants/{tenant}/agents/{agent}/render", p));

  return (
    <div className="space-y-6">
      <PageHeader title={name} back={{ href: `/tenants/${encodeURIComponent(tenant)}`, label: tenant }} />
      <Card id="detail" title={t("detail")}>
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted">{t("state")}</dt>
            <dd>{agent.compliant == null ? <Badge>{t("unknown")}</Badge> : agent.compliant ? <Badge tone="ok">{t("compliant")}</Badge> : <Badge tone="bad">{t("drifted")}</Badge>}</dd>
          </div>
          <div>
            <dt className="text-muted">{t("tenant")}</dt>
            <dd>{tenant}</dd>
          </div>
          <div>
            <dt className="text-muted">{t("groups")}</dt>
            <dd>{agent.groups.join(", ") || "—"}</dd>
          </div>
          <div>
            <dt className="text-muted">{t("proxy")}</dt>
            <dd>{agent.proxy ?? t("direct")}</dd>
          </div>
          <div>
            <dt className="text-muted">{t("effectiveVersion")}</dt>
            <dd>{agent.effective_version}</dd>
          </div>
          <div>
            <dt className="text-muted">{t("reportedVersion")}</dt>
            <dd>{agent.reported_version ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-muted">{t("reportedAt")}</dt>
            <dd>{stamp(agent.reported_at)}</dd>
          </div>
        </dl>
      </Card>
      {resolved && (
        <Card id="resolved" title={tVars("resolvedTitle")}>
          <p className="mb-3 text-xs text-muted">{tVars("resolvedNote")}</p>
          <Table caption={tVars("resolvedTitle")} head={[tVars("name"), tVars("value"), tVars("source"), tVars("hides")]} empty={tVars("none")}>
            {resolved.variables.map((v) => (
              <Row key={v.name}>
                <Cell mono>{v.name}</Cell>
                <Cell mono>{typeof v.value === "string" ? v.value : JSON.stringify(v.value)}</Cell>
                <Cell>
                  {v.source} {v.locked && <Badge tone="ok">{tVars("constant")}</Badge>}
                </Cell>
                <Cell>{[...v.overrides, ...v.ignored.map((i) => `${i} (${tVars("ignored")})`)].join(", ") || "—"}</Cell>
              </Row>
            ))}
          </Table>
          {resolved.conflicts.length > 0 && (
            <ul className="mt-3 list-disc pl-5 text-sm text-danger">
              {resolved.conflicts.map((c, i) => (
                <li key={i}>
                  {c.what}: {c.resolution}
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
      {preview && (
        <Card id="render" title={tVars("renderTitle")}>
          <p className="mb-3 text-xs text-muted">{tVars("renderNote")}</p>
          {preview.templates.length === 0 ? (
            <Notice>{tVars("noTemplates")}</Notice>
          ) : (
            <div className="space-y-4">
              {preview.templates.map((r) => (
                <div key={r.resource}>
                  <h3 className="mb-1 text-sm font-medium">
                    {r.resource} → <span className="font-mono">{r.dest}</span>
                  </h3>
                  {r.error ? (
                    <p role="alert" className="rounded-md border border-danger p-3 font-mono text-xs text-danger">
                      {r.error}
                    </p>
                  ) : (
                    <pre className="max-h-96 overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-xs">{r.output}</pre>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
