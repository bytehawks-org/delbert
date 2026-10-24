"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Icon } from "@/components/ui/icons";

/**
 * The frame of every signed-in screen: a fixed sidebar on wide screens, an off-canvas one below
 * `lg` opened from the top bar. A closed off-canvas sidebar is `invisible`, so keyboard focus
 * never lands in it.
 */
export function Shell({ brand, nav, topbar, children, labels }: { brand: React.ReactNode; nav: React.ReactNode; topbar: React.ReactNode; children: React.ReactNode; labels: { open: string; close: string } }) {
  const [open, setOpen] = useState(false);
  const path = usePathname();
  useEffect(() => setOpen(false), [path]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <div className="min-h-screen lg:pl-64">
      <aside
        id="sidebar"
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col bg-side text-side-fg transition-transform duration-200 lg:visible lg:translate-x-0 ${open ? "visible translate-x-0" : "invisible -translate-x-full"}`}
      >
        <div className="flex h-16 shrink-0 items-center justify-between px-5">
          {brand}
          <button type="button" onClick={() => setOpen(false)} aria-label={labels.close} className="rounded-md p-1 text-side-fg hover:bg-side-hover lg:hidden">
            <Icon name="close" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-3 pb-6 pt-2">{nav}</div>
      </aside>
      {open && <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" aria-hidden="true" onClick={() => setOpen(false)} />}
      <div className="flex min-h-screen min-w-0 flex-col">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border bg-surface/90 px-4 backdrop-blur sm:px-6">
          <button type="button" onClick={() => setOpen(true)} aria-expanded={open} aria-controls="sidebar" aria-label={labels.open} className="rounded-md p-2 hover:bg-surface-2 lg:hidden">
            <Icon name="menu" />
          </button>
          {topbar}
        </header>
        {children}
      </div>
    </div>
  );
}
