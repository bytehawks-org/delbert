import { getTranslations } from "next-intl/server";

export default async function NotFound() {
  const t = await getTranslations("nav");
  return (
    <main className="mx-auto max-w-sm px-4 py-20 text-center">
      <p className="text-5xl font-semibold">404</p>
      <a href="/" className="mt-6 inline-block text-accent underline">{t("dashboard")}</a>
    </main>
  );
}
