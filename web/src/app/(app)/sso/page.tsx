import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { SsoPanel } from "@/components/sso-panel";
import { Notice, PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { canGlobal } from "@/lib/perm";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("sso"))("title") };
}

export default async function Sso() {
  const { me, token } = await requireMe();
  const t = await getTranslations("sso");
  const api = core(token);
  const [providers, roles, tenants] = await Promise.all([api.GET("/v1/sso/providers"), api.GET("/v1/roles"), api.GET("/v1/tenants")]);
  const [p, r, tn] = [unwrap(providers), unwrap(roles), unwrap(tenants)];
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      {p ? <SsoPanel providers={p} roles={(r ?? []).map((x) => x.name)} tenants={(tn ?? []).map((x) => x.name)} canWrite={canGlobal(me, "sso:write")} /> : <Notice>{t("denied")}</Notice>}
    </>
  );
}
