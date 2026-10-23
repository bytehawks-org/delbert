import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { core } from "@/lib/core";
import { requireMe } from "@/lib/me";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("dashboard"))("title") };
}

export default async function Dashboard() {
  const { me, token } = await requireMe();
  const t = await getTranslations("dashboard");
  const api = core(token);

  const tenants = (await api.GET("/v1/tenants")).data ?? [];
  // A first look at fleet health; the real views come with the next milestone.
  const lists = await Promise.all(tenants.slice(0, 25).map((x) => api.GET("/v1/tenants/{tenant}/agents", { params: { path: { tenant: x.name } } }).then((r) => r.data ?? [])));
  const agents = lists.flat();
  const compliant = agents.filter((a) => a.compliant === true).length;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">{t("welcome", { name: me.username })}</h1>
      </div>
      <div className="grid gap-6 md:grid-cols-2">
        <section aria-labelledby="account" className="rounded-lg border border-border bg-surface p-5">
          <h2 id="account" className="mb-3 text-lg font-medium">{t("account")}</h2>
          <dl className="space-y-3 text-sm">
            <div>
              <dt className="text-muted">{t("roles")}</dt>
              <dd>
                {me.assignments.length === 0 ? (
                  t("noRoles")
                ) : (
                  <ul className="list-disc pl-5">
                    {me.assignments.map((a) => (
                      <li key={`${a.role}/${a.tenant ?? ""}`}>
                        <span className="font-medium">{a.role}</span> · {a.tenant ? t("scopeTenant", { tenant: a.tenant }) : t("scopeGlobal")}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
            <div>
              <dt className="text-muted">{t("mfa")}</dt>
              <dd className={me.mfa_enabled ? "text-ok" : ""}>{me.mfa_enabled ? t("mfaOn") : t("mfaOff")}</dd>
            </div>
          </dl>
        </section>
        <section aria-labelledby="overview" className="rounded-lg border border-border bg-surface p-5">
          <h2 id="overview" className="mb-3 text-lg font-medium">{t("overview")}</h2>
          <dl className="grid grid-cols-3 gap-3 text-sm">
            <div>
              <dt className="text-muted">{t("tenants")}</dt>
              <dd className="text-2xl font-semibold" data-testid="tenant-count">{tenants.length}</dd>
            </div>
            <div>
              <dt className="text-muted">{t("agents")}</dt>
              <dd className="text-2xl font-semibold" data-testid="agent-count">{agents.length}</dd>
            </div>
            <div>
              <dt className="text-muted">{t("compliant")}</dt>
              <dd className="text-2xl font-semibold text-ok">{compliant}</dd>
            </div>
          </dl>
          <p className="mt-4 text-sm">
            <Link href="/agents?state=attention" className="text-accent hover:underline">
              {agents.length - compliant} {t("needsAttention")} →
            </Link>
          </p>
        </section>
      </div>
    </div>
  );
}
