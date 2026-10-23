import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { PolicyEditor } from "@/components/policy-editor";
import { Notice, PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { can } from "@/lib/perm";

type Props = { params: Promise<{ tenant: string; name: string }>; searchParams: Promise<{ version?: string }> };

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("editor"))("editTitle") };
}

/** A new version starts from the chosen one (default: the live one) and is compared with the live one. */
export default async function EditPolicy({ params, searchParams }: Props) {
  const raw = await params;
  const tenant = decodeURIComponent(raw.tenant);
  const name = decodeURIComponent(raw.name);
  const { me, token } = await requireMe();
  const t = await getTranslations("editor");
  const back = { href: `/tenants/${encodeURIComponent(tenant)}/policies/${encodeURIComponent(name)}`, label: name };
  if (!can(me, "policies:write", tenant)) return <><PageHeader title={t("editTitle")} back={back} /><Notice>{t("denied")}</Notice></>;

  const api = core(token);
  const path = { tenant, name };
  const versions = unwrap(await api.GET("/v1/tenants/{tenant}/policies/{name}/versions", { params: { path } })) ?? [];
  const live = versions.find((v) => v.active) ?? [...versions].sort((a, b) => b.version - a.version)[0];
  const wanted = Number((await searchParams).version) || live?.version;
  const get = async (version?: number) => (version ? unwrap(await api.GET("/v1/tenants/{tenant}/policies/{name}/versions/{version}", { params: { path: { ...path, version } } }))?.yaml ?? null : null);
  const [start, base] = await Promise.all([get(wanted), get(live?.version)]);
  return (
    <>
      <PageHeader title={t("editTitle")} subtitle={start ? t("startsFrom", { version: wanted ?? 0 }) : undefined} back={back} />
      <PolicyEditor tenant={tenant} initial={start ?? ""} base={base} baseLabel={live ? `v${live.version}` : ""} />
    </>
  );
}
