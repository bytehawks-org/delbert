"use client";

import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

type Step = "password" | "mfa";
const KNOWN = ["invalid", "throttled", "invalidCode", "unavailable", "expired"] as const;

const inputClass = "w-full rounded-md border border-border bg-surface px-3 py-2 text-fg placeholder:text-muted";
const buttonClass = "w-full rounded-md bg-accent px-3 py-2 font-medium text-accent-fg disabled:opacity-60";

export function LoginForm({ providers, initialError }: { providers: { name: string; display_name: string }[]; initialError?: string }) {
  const t = useTranslations("login");
  const router = useRouter();
  const [step, setStep] = useState<Step>("password");
  const [error, setError] = useState<string | undefined>(initialError);
  const [busy, setBusy] = useState(false);
  // Until the page is interactive the form must not be submittable: a native submit would put the
  // password in the URL. (The button stays disabled, which also blocks submitting with Enter.)
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);

  async function post(url: string, body: object): Promise<{ ok: boolean; data: { error?: string; mfaRequired?: boolean } }> {
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      return { ok: res.ok, data: await res.json().catch(() => ({})) };
    } catch {
      return { ok: false, data: { error: "unavailable" } };
    }
  }

  function show(code?: string) {
    setError(code && (KNOWN as readonly string[]).includes(code) ? code : "generic");
  }

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(undefined);
    const { ok, data } =
      step === "password"
        ? await post("/api/auth/login", { username: form.get("username"), password: form.get("password") })
        : await post("/api/auth/mfa", { code: form.get("code") });
    setBusy(false);
    if (!ok) return show(data.error);
    if (step === "password" && data.mfaRequired) return setStep("mfa");
    router.replace("/");
    router.refresh();
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">{step === "password" ? t("title") : t("mfaTitle")}</h1>
      <form onSubmit={submit} method="post" className="space-y-4" noValidate>
        {step === "password" ? (
          <>
            <div className="space-y-1">
              <label htmlFor="username" className="text-sm font-medium">{t("username")}</label>
              <input id="username" name="username" autoComplete="username" autoFocus required className={inputClass} />
            </div>
            <div className="space-y-1">
              <label htmlFor="password" className="text-sm font-medium">{t("password")}</label>
              <input id="password" name="password" type="password" autoComplete="current-password" required className={inputClass} />
            </div>
          </>
        ) : (
          <div className="space-y-1">
            <p className="text-sm text-muted">{t("mfaHelp")}</p>
            <label htmlFor="code" className="text-sm font-medium">{t("mfaCode")}</label>
            <input id="code" name="code" inputMode="text" autoComplete="one-time-code" autoFocus required className={inputClass} />
          </div>
        )}
        <p role="alert" aria-live="polite" className="min-h-5 text-sm text-danger">
          {error ? (error.startsWith("sso:") ? t("errors.sso", { reason: error.slice(4) }) : t(`errors.${error}`)) : null}
        </p>
        <button type="submit" disabled={busy || !ready} className={buttonClass}>
          {step === "password" ? (busy ? t("submitting") : t("submit")) : t("mfaSubmit")}
        </button>
      </form>
      {step === "password" && providers.length > 0 ? (
        <div className="space-y-3">
          <p className="text-center text-sm text-muted">{t("ssoSeparator")}</p>
          {providers.map((p) => (
            <a
              key={p.name}
              href={`/api/auth/sso/${encodeURIComponent(p.name)}`}
              className="block w-full rounded-md border border-border bg-surface px-3 py-2 text-center font-medium"
            >
              {t("ssoWith", { provider: p.display_name })}
            </a>
          ))}
        </div>
      ) : null}
    </div>
  );
}
