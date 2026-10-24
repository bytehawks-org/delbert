import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { Badge, Card, Cell, Row, Stat, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("dashboard"))("title") };
}

/** An agent (or proxy) silent for longer than this is shown as unreachable. */
const STALE_SECS = Number(process.env.WEB_STALE_MINUTES ?? 10) * 60;

export default async function Dashboard() {
  const { me, token } = await requireMe();
  const t = await getTranslations("dashboard");
  const api = core(token);
  const now = Math.floor(Date.now() / 1000); // for the proxies' last contact

  const [overview, proxies, activity, sources] = await Promise.all([
    api.GET("/v1/overview", { params: { query: { stale_secs: STALE_SECS } } }).then(unwrap),
    api.GET("/v1/proxies").then(unwrap),
    api.GET("/v1/audit", { params: { query: { limit: 10 } } }).then(unwrap),
    api.GET("/v1/content/sources").then(unwrap),
  ]);
  // The overview is one query over every tenant the user can reach (no per-tenant requests, no cap).
  const { tenants = 0, agents = 0, compliant = 0, drifted = 0, silent = 0, attention = [] } = overview ?? {};
  const failingSources = (sources ?? []).filter((s) => s.last_error);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">{t("welcome", { name: me.username })}</h1>

      <section aria-label={t("overview")}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
          <Stat label={t("tenants")} value={tenants} icon="tenants" testid="tenant-count" />
          <Stat label={t("agents")} value={agents} icon="agents" testid="agent-count" />
          <Stat label={t("compliant")} value={compliant} icon="ok" tone="ok" />
          <Stat label={t("drifted")} value={drifted} icon="alert" tone={drifted ? "bad" : "neutral"} />
          <Stat label={t("silent")} value={silent} icon="clock" tone={silent ? "bad" : "neutral"} />
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card id="attention" title={t("attention")}>
          <Table caption={t("attention")} head={[t("agent"), t("state"), t("lastReport")]} empty={t("allGood")}>
            {attention.slice(0, 8).map((a) => (
              <Row key={`${a.tenant}/${a.name}`}>
                <Cell>
                  <Link href={`/tenants/${encodeURIComponent(a.tenant)}/agents/${encodeURIComponent(a.name)}`} className="font-medium text-accent hover:underline">
                    {a.tenant}/{a.name}
                  </Link>
                </Cell>
                <Cell>{a.state === "drifted" ? <Badge tone="bad">{t("drift")}</Badge> : <Badge>{t("silentState")}</Badge>}</Cell>
                <Cell>{stamp(a.reported_at)}</Cell>
              </Row>
            ))}
          </Table>
          {drifted + silent > 8 && (
            <p className="mt-3 text-sm">
              <Link href="/agents?state=attention" className="text-accent hover:underline">
                {t("allAttention", { count: drifted + silent })} →
              </Link>
            </p>
          )}
        </Card>

        <Card id="recent" title={t("recent")}>
          {activity ? (
            <Table caption={t("recent")} head={[t("when"), t("who"), t("what")]} empty={t("noActivity")}>
              {activity.events.map((e) => (
                <Row key={e.seq}>
                  <Cell>{stamp(e.occurred_at_micros, "us")}</Cell>
                  <Cell>{e.actor}</Cell>
                  <Cell>
                    {e.action}
                    {e.target ? <span className="text-muted"> · {e.target}</span> : null} {e.outcome !== "ok" && <Badge tone="bad">{e.outcome}</Badge>}
                  </Cell>
                </Row>
              ))}
            </Table>
          ) : (
            <p className="text-sm text-muted">{t("noAudit")}</p>
          )}
          {activity && (
            <p className="mt-3 text-sm">
              <Link href="/audit" className="text-accent hover:underline">
                {t("openAudit")} →
              </Link>
            </p>
          )}
        </Card>

        {proxies && (
          <Card id="proxies" title={t("proxies")}>
            <Table caption={t("proxies")} head={[t("name"), t("state"), t("lastSeen")]} empty={t("noProxies")}>
              {proxies.map((p) => {
                const up = p.enrolled && p.last_seen != null && now - p.last_seen <= STALE_SECS;
                return (
                  <Row key={p.name}>
                    <Cell>{p.name}</Cell>
                    <Cell>{!p.enrolled ? <Badge>{t("proxyPending")}</Badge> : up ? <Badge tone="ok">{t("proxyUp")}</Badge> : <Badge tone="bad">{t("proxyDown")}</Badge>}</Cell>
                    <Cell>{stamp(p.last_seen)}</Cell>
                  </Row>
                );
              })}
            </Table>
          </Card>
        )}

        {failingSources.length > 0 && (
          <Card id="sources" title={t("failingSources")}>
            <ul className="space-y-2 text-sm">
              {failingSources.map((s) => (
                <li key={s.name}>
                  <Link href={`/content/${encodeURIComponent(s.name)}`} className="font-medium text-accent hover:underline">
                    {s.name}
                  </Link>
                  <p className="break-all text-xs text-danger">{s.last_error}</p>
                </li>
              ))}
            </ul>
          </Card>
        )}

        <Card id="account" title={t("account")}>
          <dl className="space-y-3 text-sm">
            <div>
              <dt className="text-muted">{t("roles")}</dt>
              <dd>
                {me.assignments.length === 0 ? (
                  t("noRoles")
                ) : (
                  <ul className="list-disc pl-5">
                    {me.assignments.map((a) => (
                      <li key={`${a.role}/${a.tenant ?? ""}`}>
                        <span className="font-medium">{a.role}</span> · {a.tenant ? t("scopeTenant", { tenant: a.tenant }) : t("scopeGlobal")}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
            <div>
              <dt className="text-muted">{t("mfa")}</dt>
              <dd className={me.mfa_enabled ? "text-ok" : ""}>
                {me.mfa_enabled ? t("mfaOn") : t("mfaOff")}
                {!me.mfa_enabled && (
                  <>
                    {" "}
                    <Link href="/profile" className="text-accent hover:underline">
                      {t("setUp")}
                    </Link>
                  </>
                )}
              </dd>
            </div>
          </dl>
        </Card>
      </div>
    </div>
  );
}
