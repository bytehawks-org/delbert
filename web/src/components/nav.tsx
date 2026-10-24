"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";

const items = [
  { href: "/", key: "dashboard" },
  { href: "/tenants", key: "tenants" },
  { href: "/agents", key: "agents" },
  { href: "/proxies", key: "proxies" },
  { href: "/users", key: "users", needs: "users" },
  { href: "/roles", key: "roles", needs: "roles" },
  { href: "/audit", key: "audit" },
] as const;

/** `granted` names the governance sections the signed-in user may open (the Core enforces it anyway). */
export function MainNav({ granted }: { granted: string[] }) {
  const t = useTranslations("nav");
  const path = usePathname();
  return (
    <nav aria-label={t("main")} className="flex flex-wrap gap-4 text-sm">
      {items
        .filter((i) => !("needs" in i) || granted.includes(i.needs))
        .map(({ href, key }) => {
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
