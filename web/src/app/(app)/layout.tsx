import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { LiveRefresh } from "@/components/live-refresh";
import { LocaleSwitcher } from "@/components/locale-switcher";
import { MainNav } from "@/components/nav";
import { ThemeToggle } from "@/components/theme";
import { requireMe } from "@/lib/me";
import { canAnywhere, canGlobal } from "@/lib/perm";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const { me } = await requireMe();
  const t = await getTranslations();
  return (
    <>
      <a href="#content" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">
        {t("common.skipToContent")}
      </a>
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-6">
            <span className="text-lg font-semibold tracking-tight">{t("app.name")}</span>
            <MainNav granted={[canGlobal(me, "users:read") && "users", canGlobal(me, "roles:read") && "roles", canGlobal(me, "sso:read") && "sso", canAnywhere(me, "content:read") && "content"].filter((x): x is string => !!x)} />
          </div>
          <div className="flex flex-wrap items-center gap-4">
            <LiveRefresh />
            <LocaleSwitcher />
            <ThemeToggle />
            <Link href="/profile" className="text-sm text-muted hover:text-fg">
              <span data-testid="signed-in-as">{t("header.signedInAs", { name: me.username })}</span>
            </Link>
            <form method="post" action="/api/auth/logout">
              <button type="submit" className="rounded-md border border-border px-3 py-1.5 text-sm">
                {t("header.logout")}
              </button>
            </form>
          </div>
        </div>
      </header>
      <main id="content" className="mx-auto max-w-6xl px-4 py-8">
        {children}
      </main>
    </>
  );
}
