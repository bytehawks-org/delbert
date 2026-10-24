"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { Icon, type IconName } from "@/components/ui/icons";

type Item = { href: string; key: string; icon: IconName; needs?: string };

const groups: { key: string; items: Item[] }[] = [
  { key: "overview", items: [{ href: "/", key: "dashboard", icon: "dashboard" }] },
  {
    key: "fleet",
    items: [
      { href: "/tenants", key: "tenants", icon: "tenants" },
      { href: "/agents", key: "agents", icon: "agents" },
      { href: "/proxies", key: "proxies", icon: "proxies" },
    ],
  },
  {
    key: "content",
    items: [
      { href: "/content", key: "content", icon: "content", needs: "content" },
      { href: "/shared", key: "shared", icon: "shared", needs: "globals" },
    ],
  },
  {
    key: "administration",
    items: [
      { href: "/users", key: "users", icon: "users", needs: "users" },
      { href: "/roles", key: "roles", icon: "roles", needs: "roles" },
      { href: "/sso", key: "sso", icon: "sso", needs: "sso" },
      { href: "/audit", key: "audit", icon: "audit" },
    ],
  },
];

/** `granted` names the governance sections the signed-in user may open (the Core enforces it anyway). */
export function MainNav({ granted }: { granted: string[] }) {
  const t = useTranslations("nav");
  const path = usePathname();
  return (
    <nav aria-label={t("main")} className="space-y-6">
      {groups.map((g) => {
        const items = g.items.filter((i) => !i.needs || granted.includes(i.needs));
        if (items.length === 0) return null;
        return (
          <div key={g.key}>
            <p id={`nav-${g.key}`} className="mb-2 px-3 text-xs font-medium uppercase tracking-wider text-side-muted">
              {t(`groups.${g.key}`)}
            </p>
            <ul aria-labelledby={`nav-${g.key}`} className="space-y-0.5">
              {items.map(({ href, key, icon }) => {
                const current = href === "/" ? path === "/" : path === href || path.startsWith(`${href}/`);
                return (
                  <li key={href}>
                    <Link
                      href={href}
                      aria-current={current ? "page" : undefined}
                      className={`flex items-center gap-3 rounded-lg border-l-2 px-3 py-2 text-sm transition-colors ${current ? "border-side-accent bg-side-hover font-medium text-white" : "border-transparent text-side-fg hover:bg-side-hover hover:text-white"}`}
                    >
                      <Icon name={icon} className={`size-[18px] ${current ? "text-side-accent" : ""}`} />
                      {t(key)}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </nav>
  );
}
