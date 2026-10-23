import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { redirect } from "next/navigation";
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
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-8 px-4 py-10">
      <header>
        <p className="text-3xl font-semibold tracking-tight">{t("name")}</p>
        <p className="text-sm text-muted">{t("tagline")}</p>
      </header>
      <section className="rounded-lg border border-border bg-surface p-6 shadow-sm">
        <LoginForm providers={providers} initialError={initialError} />
      </section>
      <footer className="flex flex-wrap items-center justify-between gap-3">
        <LocaleSwitcher />
        <ThemeToggle />
      </footer>
    </main>
  );
}
