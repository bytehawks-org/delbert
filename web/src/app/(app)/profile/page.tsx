import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { ProfilePanel } from "@/components/profile-panel";
import { PageHeader } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("profile"))("title") };
}

export default async function Profile() {
  const { me, token } = await requireMe();
  const t = await getTranslations("profile");
  const api = core(token);
  const [sessions, tokens] = await Promise.all([api.GET("/v1/me/sessions"), api.GET("/v1/me/tokens")]);
  const [s, tk] = [unwrap(sessions) ?? [], unwrap(tokens)]; // tokens: null when the role lacks tokens:manage
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle", { name: me.username })} />
      <ProfilePanel
        mfaEnabled={me.mfa_enabled}
        globalPermissions={me.permissions}
        tenantPermissions={me.tenants}
        sessions={s.map((x) => ({ ...x, created: stamp(x.created_at), seen: stamp(x.last_seen) }))}
        tokens={tk && tk.map((x) => ({ ...x, expires: stamp(x.expires_at), used: x.last_used ? stamp(x.last_used) : null }))}
      />
    </>
  );
}
