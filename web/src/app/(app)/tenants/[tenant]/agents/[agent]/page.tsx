import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { Badge, Card, PageHeader } from "@/components/ui";
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
    </div>
  );
}
