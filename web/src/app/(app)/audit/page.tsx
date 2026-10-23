import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { Badge, Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

const FILTERS = ["tenant", "actor", "action", "target", "outcome"] as const;
type Search = Partial<Record<(typeof FILTERS)[number] | "before", string>>;

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("audit"))("title") };
}

export default async function Audit({ searchParams }: { searchParams: Promise<Search> }) {
  const q = await searchParams;
  const { token } = await requireMe();
  const t = await getTranslations("audit");
  const api = core(token);
  const query = { tenant: q.tenant || undefined, actor: q.actor || undefined, action: q.action || undefined, target: q.target || undefined, outcome: q.outcome || undefined, before: q.before ? Number(q.before) : undefined, limit: 50 };
  const page = unwrap(await api.GET("/v1/audit", { params: { query } }));
  if (!page) return <Notice>{t("denied")}</Notice>;
  const chain = unwrap(await api.GET("/v1/audit/verify"));

  // Keep the filters when paging.
  const keep = new URLSearchParams(Object.entries(q).filter(([k, v]) => k !== "before" && v) as [string, string][]);
  const older = page.next != null ? `/audit?${new URLSearchParams({ ...Object.fromEntries(keep), before: String(page.next) })}` : null;

  return (
    <div className="space-y-6">
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      {chain && (
        <Card id="chain" title={t("chain")}>
          {chain.first_bad == null ? (
            <p className="text-sm">
              <Badge tone="ok">{t("chainOk")}</Badge> <span className="ml-2 text-muted">{t("chainEvents", { count: chain.events })}</span>
            </p>
          ) : (
            <p className="text-sm">
              <Badge tone="bad">{t("chainBroken")}</Badge> <span className="ml-2">{t("chainFirstBad", { seq: chain.first_bad })}</span>
            </p>
          )}
        </Card>
      )}
      <form method="get" className="flex flex-wrap items-end gap-3 text-sm" aria-label={t("filters")}>
        {FILTERS.map((f) => (
          <label key={f} className="flex flex-col gap-1">
            <span className="text-muted">{t(`filter.${f}`)}</span>
            <input name={f} defaultValue={q[f] ?? ""} className="w-40 rounded-md border border-border bg-surface px-2 py-1.5" />
          </label>
        ))}
        <button type="submit" className="rounded-md bg-accent px-3 py-1.5 font-medium text-accent-fg">
          {t("apply")}
        </button>
        <Link href="/audit" className="px-2 py-1.5 text-muted hover:text-fg">
          {t("reset")}
        </Link>
      </form>
      <Table caption={t("title")} head={[t("when"), t("actor"), t("actionCol"), t("targetCol"), t("tenantCol"), t("outcomeCol")]} empty={t("none")}>
        {page.events.map((e) => (
          <Row key={e.seq}>
            <Cell mono>{stamp(e.occurred_at_micros, "us")}</Cell>
            <Cell>{e.actor}</Cell>
            <Cell mono>{e.action}</Cell>
            <Cell>{e.target ?? "—"}</Cell>
            <Cell>{e.tenant ?? "—"}</Cell>
            <Cell>
              <Badge tone={e.outcome === "ok" ? "ok" : "bad"}>{e.outcome}</Badge>
            </Cell>
          </Row>
        ))}
      </Table>
      {older && (
        <Link href={older} className="inline-block text-sm text-accent hover:underline" rel="next">
          {t("older")} →
        </Link>
      )}
    </div>
  );
}
