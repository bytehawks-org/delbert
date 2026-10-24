"use client";

import { usePathname, useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useEffect, useState } from "react";

/** Pages with a form in progress are left alone: a refresh must never disturb an edit. */
const QUIET = /\/(new|edit)$/;
/** Without the stream (blocked, expired session, old proxy) the page still refreshes by itself. */
const FALLBACK_MS = 30_000;
const DEBOUNCE_MS = 1_200;

/**
 * Keeps the server-rendered page current: when the Core says something changed it re-renders
 * the route (React state in forms is kept). Falls back to polling if the stream is not available.
 */
export function LiveRefresh() {
  const t = useTranslations("live");
  const router = useRouter();
  const path = usePathname();
  const [state, setState] = useState<"connecting" | "live" | "polling">("connecting");
  const quiet = QUIET.test(path);

  useEffect(() => {
    if (quiet) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let poll: ReturnType<typeof setInterval> | undefined;
    const refresh = () => {
      clearTimeout(timer);
      timer = setTimeout(() => router.refresh(), DEBOUNCE_MS);
    };
    const startPolling = () => {
      setState("polling");
      poll ??= setInterval(() => document.visibilityState === "visible" && router.refresh(), FALLBACK_MS);
    };

    if (typeof EventSource === "undefined") {
      startPolling();
      return () => clearInterval(poll);
    }
    const source = new EventSource("/api/stream");
    source.onopen = () => {
      setState("live");
      clearInterval(poll);
      poll = undefined;
    };
    source.onmessage = refresh;
    // EventSource retries on its own; if it gives up (401, 502) we poll instead.
    source.onerror = () => {
      if (source.readyState === EventSource.CLOSED) startPolling();
      else setState("connecting");
    };
    const onVisible = () => document.visibilityState === "visible" && refresh();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      source.close();
      clearTimeout(timer);
      clearInterval(poll);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [router, quiet]);

  if (quiet) return null;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted" data-testid="live-state" data-state={state}>
      <span aria-hidden className={`inline-block size-2 rounded-full ${state === "live" ? "bg-ok" : "bg-muted"}`} />
      {t(state)}
    </span>
  );
}
