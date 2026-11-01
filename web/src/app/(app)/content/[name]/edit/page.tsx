import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { RepoEditor } from "@/components/repo-editor";
import { Notice, PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { can, canGlobal } from "@/lib/perm";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

export default async function Edit({ params }: Props) {
  const name = decodeURIComponent((await params).name);
  const { me, token } = await requireMe();
  const t = await getTranslations("repo");
  const api = core(token);
  const source = unwrap(await api.GET("/v1/content/sources/{name}", { params: { path: { name } } }));
  const tree = source ? unwrap(await api.GET("/v1/content/sources/{name}/files", { params: { path: { name } } })) : null;
  return (
    <>
      <PageHeader title={name} subtitle={t("subtitle")} back={{ href: "/content", label: t("back") }} />
      {source && tree ? (
        <RepoEditor
          source={name}
          kind={source.kind}
          tenant={source.tenant ?? null}
          files={tree.files}
          revision={tree.revision}
          writable={tree.writable}
          canEdit={source.tenant ? can(me, "content:edit", source.tenant) : canGlobal(me, "content:edit")}
        />
      ) : (
        <Notice>{t("unavailable")}</Notice>
      )}
    </>
  );
}
