"use client";

import { useTranslations } from "next-intl";
import { useEffect, useState } from "react";

type Mode = "light" | "dark" | "system";

function apply(mode: Mode) {
  const dark = mode === "dark" || (mode === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}

/** Light, dark or follow the system; the choice is kept in this browser only. */
export function ThemeToggle() {
  const t = useTranslations("header");
  const [mode, setMode] = useState<Mode>("system");

  useEffect(() => {
    try {
      const stored = localStorage.getItem("theme");
      if (stored === "light" || stored === "dark") setMode(stored);
    } catch {
      /* storage can be blocked: the default applies */
    }
  }, []);

  function choose(next: Mode) {
    setMode(next);
    try {
      if (next === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", next);
    } catch {
      /* ignore */
    }
    apply(next);
  }

  return (
    <label className="flex items-center gap-2 text-sm text-muted">
      <span className="sr-only">{t("theme")}</span>
      <select
        value={mode}
        onChange={(e) => choose(e.target.value as Mode)}
        className="rounded-md border border-border bg-surface px-1.5 py-1.5 text-xs text-fg sm:px-2 sm:text-sm"
      >
        <option value="system">{t("themeSystem")}</option>
        <option value="light">{t("themeLight")}</option>
        <option value="dark">{t("themeDark")}</option>
      </select>
    </label>
  );
}
