import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { ContentSources } from "@/components/content-sources";
import { Notice, PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { canAnywhere } from "@/lib/perm";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("content"))("title") };
}

export default async function Content() {
  const { me, token } = await requireMe();
  const t = await getTranslations("content");
  const api = core(token);
  const [sources, tenants] = await Promise.all([api.GET("/v1/content/sources"), api.GET("/v1/tenants")]);
  const [s, tn] = [unwrap(sources), unwrap(tenants)];
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      {s ? (
        <ContentSources
          sources={s.map((x) => ({ ...x, syncedLabel: stamp(x.last_sync_at) }))}
          tenants={(tn ?? []).map((x) => x.name)}
          canWrite={canAnywhere(me, "content:write")}
          canSync={canAnywhere(me, "content:sync")}
        />
      ) : (
        <Notice>{t("denied")}</Notice>
      )}
    </>
  );
}
