import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { Badge, Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

const FILTERS = ["tenant", "actor", "action", "target", "outcome"] as const;
type Search = Partial<Record<(typeof FILTERS)[number] | "before", string>>;

/** The event's details, one line per field. Agent events lead with what was acted on, what was found and how long it took. */
function Details({ details, label }: { details: unknown; label: string }) {
  if (details == null || typeof details !== "object") return null;
  const entries = Object.entries(details as Record<string, unknown>).filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && v.length === 0));
  if (entries.length === 0) return null;
  const text = (v: unknown) => (Array.isArray(v) ? v.join("; ") : typeof v === "object" ? JSON.stringify(v) : String(v));
  return (
    <details>
      <summary className="cursor-pointer text-accent hover:underline">{label}</summary>
      <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
        {entries.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="break-all font-mono">{text(v)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

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
        <button type="submit" className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg">
          {t("apply")}
        </button>
        <Link href="/audit" className="px-2 py-1.5 text-muted hover:text-fg">
          {t("reset")}
        </Link>
      </form>
      <Table caption={t("title")} head={[t("when"), t("actor"), t("actionCol"), t("targetCol"), t("tenantCol"), t("outcomeCol"), t("detailsCol")]} empty={t("none")}>
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
            <Cell>
              <Details details={e.details} label={t("show")} />
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
