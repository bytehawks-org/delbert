"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";

const items = [
  { href: "/", key: "dashboard" },
  { href: "/tenants", key: "tenants" },
  { href: "/agents", key: "agents" },
  { href: "/proxies", key: "proxies" },
  { href: "/audit", key: "audit" },
] as const;

export function MainNav() {
  const t = useTranslations("nav");
  const path = usePathname();
  return (
    <nav aria-label={t("main")} className="flex flex-wrap gap-4 text-sm">
      {items.map(({ href, key }) => {
        const current = href === "/" ? path === "/" : path === href || path.startsWith(`${href}/`);
        return (
          <Link key={href} href={href} aria-current={current ? "page" : undefined} className={current ? "font-medium text-accent" : "text-muted hover:text-fg"}>
            {t(key)}
          </Link>
        );
      })}
    </nav>
  );
}
