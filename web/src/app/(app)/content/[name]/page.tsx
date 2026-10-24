import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { Badge, Cell, Notice, PageHeader, Row, Table, UnifiedDiff } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

type Props = { params: Promise<{ name: string }>; searchParams: Promise<{ snapshot?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

const tone = (status: string) => (status === "applied" ? "ok" : status === "unchanged" ? "neutral" : "bad");

export default async function Source({ params, searchParams }: Props) {
  const name = decodeURIComponent((await params).name);
  const wanted = Number((await searchParams).snapshot);
  const { token } = await requireMe();
  const t = await getTranslations("content");
  const api = core(token);
  const p = { params: { path: { name } } };
  const snapshots = unwrap(await api.GET("/v1/content/sources/{name}/snapshots", p));
  const detail = snapshots && wanted ? unwrap(await api.GET("/v1/content/sources/{name}/snapshots/{id}", { params: { path: { name, id: wanted } } })) : null;

  return (
    <>
      <PageHeader title={name} subtitle={t("historyHelp")} back={{ href: "/content", label: t("title") }} />
      {snapshots ? (
        <div className="space-y-6">
          <Table caption={t("history")} head={[t("revision"), t("state"), t("actor"), t("when"), ""]} empty={t("noSnapshots")}>
            {snapshots.map((s) => (
              <Row key={s.id}>
                <Cell mono>{s.revision.slice(0, 12)}</Cell>
                <Cell>
                  <Badge tone={tone(s.status)}>{s.status}</Badge>
                  {s.error && <p className="mt-1 break-all text-xs text-danger">{s.error}</p>}
                </Cell>
                <Cell>{s.actor}</Cell>
                <Cell>{stamp(s.created_at)}</Cell>
                <Cell>
                  <a href={`/content/${encodeURIComponent(name)}?snapshot=${s.id}`} className="text-accent hover:underline">
                    {t("changes")}
                  </a>
                </Cell>
              </Row>
            ))}
          </Table>
          {detail && (
            <section aria-labelledby="changes" className="space-y-3">
              <h2 id="changes" className="text-lg font-medium">
                {t("changesOf", { revision: detail.revision.slice(0, 12) })}
              </h2>
              {detail.changes.length === 0 && <p className="text-sm text-muted">{t("noChanges")}</p>}
              {detail.changes.map((c) => (
                <div key={`${c.tenant}/${c.kind}/${c.name}`} className="space-y-1">
                  <p className="text-sm">
                    <span className="font-medium">{c.tenant}</span> · {c.kind} <span className="font-mono">{c.name}</span> · <Badge>{c.change}</Badge>
                    {c.version != null && <span className="text-muted"> → v{c.version}</span>}
                    {!c.applied && <span className="text-muted"> ({t("notApplied")})</span>}
                  </p>
                  {c.diff && <UnifiedDiff text={c.diff} />}
                </div>
              ))}
            </section>
          )}
        </div>
      ) : (
        <Notice>{t("denied")}</Notice>
      )}
    </>
  );
}
