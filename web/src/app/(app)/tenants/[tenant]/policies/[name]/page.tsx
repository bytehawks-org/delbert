import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { Badge, Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

type Props = { params: Promise<{ tenant: string; name: string }>; searchParams: Promise<{ version?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

export default async function Policy({ params, searchParams }: Props) {
  const raw = await params;
  const tenant = decodeURIComponent(raw.tenant);
  const name = decodeURIComponent(raw.name);
  const wanted = Number((await searchParams).version);
  const { token } = await requireMe();
  const t = await getTranslations("policies");
  const api = core(token);
  const path = { tenant, name };

  const versions = unwrap(await api.GET("/v1/tenants/{tenant}/policies/{name}/versions", { params: { path } }));
  if (!versions) return <Notice>{t("denied")}</Notice>;
  const sorted = [...versions].sort((a, b) => b.version - a.version);
  // Default to the version that is live, else the newest.
  const shown = sorted.find((v) => v.version === wanted) ?? sorted.find((v) => v.active) ?? sorted[0];
  const detail = shown ? unwrap(await api.GET("/v1/tenants/{tenant}/policies/{name}/versions/{version}", { params: { path: { ...path, version: shown.version } } })) : null;
  const tone = (s: string) => (s === "active" ? "ok" : s === "rejected" ? "bad" : "neutral");

  return (
    <div className="space-y-6">
      <PageHeader title={name} back={{ href: `/tenants/${encodeURIComponent(tenant)}`, label: tenant }} />
      <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        <Card id="yaml" title={t("source", { version: shown?.version ?? 0 })}>
          {detail ? (
            <pre tabIndex={0} className="max-h-[32rem] overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-xs leading-relaxed" data-testid="policy-yaml">
              {detail.yaml}
            </pre>
          ) : (
            <Notice>{t("none")}</Notice>
          )}
        </Card>
        <div className="space-y-6">
          <Card id="versions" title={t("versions")}>
            <Table caption={t("versions")} head={[t("version"), t("state"), t("by")]} empty={t("none")}>
              {sorted.map((v) => (
                <Row key={v.version}>
                  <Cell>
                    <a href={`?version=${v.version}`} aria-current={v.version === shown?.version ? "true" : undefined} className={v.version === shown?.version ? "font-medium text-accent" : "hover:underline"}>
                      v{v.version}
                    </a>
                  </Cell>
                  <Cell>
                    <Badge tone={tone(v.state)}>{v.state}</Badge>
                    {v.active ? <span className="ml-1"><Badge tone="ok">{t("live")}</Badge></span> : null}
                  </Cell>
                  <Cell>{v.created_by}</Cell>
                </Row>
              ))}
            </Table>
          </Card>
          {detail && detail.events.length > 0 && (
            <Card id="history" title={t("history", { version: shown!.version })}>
              <ol className="space-y-2 text-sm">
                {detail.events.map((e, i) => (
                  <li key={i}>
                    <span className="font-medium">{e.event}</span> · {e.actor}
                    <div className="text-xs text-muted">
                      {stamp(e.at)}
                      {e.comment ? ` — ${e.comment}` : ""}
                    </div>
                  </li>
                ))}
              </ol>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
