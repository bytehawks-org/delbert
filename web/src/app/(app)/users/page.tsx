import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { UsersPanel } from "@/components/users-panel";
import { Notice, PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { canGlobal } from "@/lib/perm";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("users"))("title") };
}

export default async function Users() {
  const { me, token } = await requireMe();
  const t = await getTranslations("users");
  const api = core(token);
  const [users, roles, tenants] = await Promise.all([api.GET("/v1/users"), api.GET("/v1/roles"), api.GET("/v1/tenants")]);
  const [u, r, tn] = [unwrap(users), unwrap(roles), unwrap(tenants)];
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      {u && r ? <UsersPanel users={u} me={me.username} roles={r.map((x) => ({ name: x.name, scope: x.scope }))} tenants={(tn ?? []).map((x) => x.name)} canWrite={canGlobal(me, "users:write")} /> : <Notice>{t("denied")}</Notice>}
    </>
  );
}
