import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { AgentsTable } from "@/components/agents-table";
import { PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

type Props = { searchParams: Promise<{ state?: string }> };

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("agents"))("title") };
}

export default async function Agents({ searchParams }: Props) {
  const { state } = await searchParams;
  const { token } = await requireMe();
  const t = await getTranslations("agents");
  const api = core(token);
  const tenants = unwrap(await api.GET("/v1/tenants")) ?? [];
  const all = (
    await Promise.all(
      tenants.map(async (x) => (unwrap(await api.GET("/v1/tenants/{tenant}/agents", { params: { path: { tenant: x.name } } })) ?? []).map((a) => ({ ...a, tenant: x.name }))),
    )
  ).flat();
  const shown = all.filter((a) => (state === "compliant" ? a.compliant === true : state === "attention" ? a.compliant !== true : true));
  const filters = [
    ["", t("filterAll")],
    ["compliant", t("compliant")],
    ["attention", t("filterAttention")],
  ] as const;
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle", { count: all.length })} />
      <nav aria-label={t("filters")} className="mb-4 flex gap-3 text-sm">
        {filters.map(([value, label]) => (
          <Link key={value} href={value ? `/agents?state=${value}` : "/agents"} aria-current={(state ?? "") === value ? "true" : undefined} className={(state ?? "") === value ? "font-medium text-accent" : "text-muted hover:text-fg"}>
            {label}
          </Link>
        ))}
      </nav>
      <AgentsTable agents={shown} showTenant />
    </>
  );
}
