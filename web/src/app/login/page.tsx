import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { redirect } from "next/navigation";
import { Brand } from "@/components/brand";
import { LoginForm } from "@/components/login-form";
import { LocaleSwitcher } from "@/components/locale-switcher";
import { ThemeToggle } from "@/components/theme";
import { core } from "@/lib/core";
import { getSession } from "@/lib/session";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("login"))("title") };
}

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ [key: string]: string | string[] | undefined }> }) {
  const query = await searchParams;
  if ((await getSession())?.mfaPending === false) redirect("/");
  const t = await getTranslations("app");
  const providers = (await core().GET("/v1/auth/sso/providers").catch(() => ({ data: undefined }))).data ?? [];
  const sso = typeof query.sso_error === "string" ? `sso:${query.sso_error}` : undefined;
  const initialError = sso ?? (query.expired ? "expired" : undefined);

  return (
    <main className="grid min-h-screen lg:grid-cols-[minmax(0,5fr)_minmax(0,4fr)]">
      <section aria-label={t("by")} className="hidden flex-col justify-between bg-side p-12 text-white lg:flex">
        <Brand name={t("name")} by={t("by")} />
        <div className="max-w-md">
          <span className="brand-mark mb-8 block size-40 text-side-accent opacity-90" aria-hidden="true" />
          <p className="font-display text-3xl font-semibold leading-snug tracking-tight">{t("tagline")}</p>
        </div>
        <p className="text-xs text-side-muted">{t("by")}</p>
      </section>
      <div className="flex flex-col justify-center gap-8 px-6 py-10 sm:px-12">
        <div className="mx-auto w-full max-w-sm space-y-8">
          <header className="lg:hidden">
            <Brand name={t("name")} by={t("by")} className="text-fg" />
            <p className="mt-3 text-sm text-muted">{t("tagline")}</p>
          </header>
          <section className="rounded-xl border border-border bg-surface p-6 shadow-sm">
            <LoginForm providers={providers} initialError={initialError} />
          </section>
          <footer className="flex flex-wrap items-center justify-between gap-3">
            <LocaleSwitcher />
            <ThemeToggle />
          </footer>
        </div>
      </div>
    </main>
  );
}
