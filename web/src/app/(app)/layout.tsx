import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { LiveRefresh } from "@/components/live-refresh";
import { LocaleSwitcher } from "@/components/locale-switcher";
import { Brand } from "@/components/brand";
import { MainNav } from "@/components/nav";
import { Shell } from "@/components/shell";
import { Icon } from "@/components/ui/icons";
import { ThemeToggle } from "@/components/theme";
import { requireMe } from "@/lib/me";
import { canAnywhere, canGlobal } from "@/lib/perm";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const { me } = await requireMe();
  const t = await getTranslations();
  const granted = [canGlobal(me, "users:read") && "users", canGlobal(me, "roles:read") && "roles", canGlobal(me, "sso:read") && "sso", canAnywhere(me, "content:read") && "content", canGlobal(me, "globals:read") && "globals"].filter((x): x is string => !!x);
  return (
    <>
      <a href="#content" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">
        {t("common.skipToContent")}
      </a>
      <Shell
        labels={{ open: t("header.openMenu"), close: t("header.closeMenu") }}
        brand={<Brand name={t("app.name")} by={t("app.by")} className="text-white" />}
        nav={<MainNav granted={granted} />}
        topbar={
          <>
            <LiveRefresh />
            <div className="ml-auto flex items-center gap-3">
              <LocaleSwitcher />
              <ThemeToggle />
              <Link href="/profile" className="flex items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-surface-2">
                <span aria-hidden="true" className="flex size-8 items-center justify-center rounded-full bg-brand/15 text-xs font-semibold uppercase text-accent">
                  {me.username.slice(0, 2)}
                </span>
                <span data-testid="signed-in-as" className="hidden sm:inline">
                  {t("header.signedInAs", { name: me.username })}
                </span>
              </Link>
              <form method="post" action="/api/auth/logout">
                <button type="submit" aria-label={t("header.logout")} className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-surface-2">
                  <Icon name="logout" className="size-4" />
                  <span className="hidden md:inline">{t("header.logout")}</span>
                </button>
              </form>
            </div>
          </>
        }
      >
        <main id="content" className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6">
          {children}
        </main>
      </Shell>
    </>
  );
}
