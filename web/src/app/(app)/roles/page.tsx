import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { RolesPanel } from "@/components/roles-panel";
import { Notice, PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { canGlobal } from "@/lib/perm";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("roles"))("title") };
}

export default async function Roles() {
  const { me, token } = await requireMe();
  const t = await getTranslations("roles");
  const api = core(token);
  const [roles, catalog] = await Promise.all([api.GET("/v1/roles"), api.GET("/v1/permissions")]);
  const [r, c] = [unwrap(roles), unwrap(catalog)];
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      {r && c ? <RolesPanel roles={r} catalog={c} canWrite={canGlobal(me, "roles:write")} /> : <Notice>{t("denied")}</Notice>}
    </>
  );
}
