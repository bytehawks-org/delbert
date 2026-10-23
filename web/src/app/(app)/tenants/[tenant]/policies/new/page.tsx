import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { PolicyEditor } from "@/components/policy-editor";
import { Notice, PageHeader } from "@/components/ui";
import { requireMe } from "@/lib/me";
import { can } from "@/lib/perm";

type Props = { params: Promise<{ tenant: string }> };

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("editor"))("newTitle") };
}

export default async function NewPolicy({ params }: Props) {
  const tenant = decodeURIComponent((await params).tenant);
  const { me } = await requireMe();
  const t = await getTranslations("editor");
  const template = `apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: my-policy, tenant: ${tenant} }\nspec:\n  target: { groups: [web] }\n  resources:\n    - id: motd\n      copy: { content: "Managed by Delbert\\n", dest: /etc/motd, mode: "0644" }\n`;
  return (
    <>
      <PageHeader title={t("newTitle")} back={{ href: `/tenants/${encodeURIComponent(tenant)}`, label: tenant }} />
      {can(me, "policies:write", tenant) ? <PolicyEditor tenant={tenant} initial={template} base={null} baseLabel="" /> : <Notice>{t("denied")}</Notice>}
    </>
  );
}
