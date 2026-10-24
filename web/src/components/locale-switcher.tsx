"use client";

import { useLocale, useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useTransition } from "react";

const NAMES: Record<string, string> = { en: "English", it: "Italiano" };

export function LocaleSwitcher() {
  const t = useTranslations("header");
  const locale = useLocale();
  const router = useRouter();
  const [pending, start] = useTransition();

  async function change(next: string) {
    await fetch("/api/locale", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ locale: next }) });
    start(() => router.refresh());
  }

  return (
    <label className="flex items-center gap-2 text-sm text-muted">
      <span className="sr-only">{t("language")}</span>
      <select
        value={locale}
        disabled={pending}
        onChange={(e) => change(e.target.value)}
        className="rounded-md border border-border bg-surface px-1.5 py-1.5 text-xs text-fg sm:px-2 sm:text-sm"
      >
        {Object.entries(NAMES).map(([code, name]) => (
          <option key={code} value={code}>
            {name}
          </option>
        ))}
      </select>
    </label>
  );
}
