"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Badge, Card, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

type Session = { id: string; current: boolean; ip?: string | null; user_agent?: string | null; created: string; seen: string };
type Token = { id: string; name: string; tenant?: string | null; permissions: string[]; expires: string; used: string | null };

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";
const primary = "rounded-md bg-action px-3 py-1.5 text-sm font-medium text-action-fg";

/** The signed-in user's own security settings: second factor, sessions and API tokens. */
export function ProfilePanel({
  mfaEnabled,
  globalPermissions,
  tenantPermissions,
  sessions,
  tokens,
}: {
  mfaEnabled: boolean;
  globalPermissions: string[];
  tenantPermissions: Record<string, string[]>;
  sessions: Session[];
  tokens: Token[] | null;
}) {
  const t = useTranslations("profile");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [created, setCreated] = useState<string | null>(null);
  const [scope, setScope] = useState(""); // "" = global
  const [picked, setPicked] = useState<Set<string>>(new Set());

  async function run<T>(method: "POST" | "DELETE", path: string, body?: unknown): Promise<T | null> {
    setError(null);
    const r = await callCore<T>(method, path, body);
    if (!r.ok) {
      setError(r.error ?? "?");
      return null;
    }
    router.refresh();
    return (r.data ?? ({} as T)) as T;
  }

  async function enroll() {
    const r = await run<{ secret: string; otpauth_uri: string }>("POST", "/v1/me/mfa/enroll");
    if (r) setEnrollment(r);
  }

  async function confirm(form: FormData) {
    const r = await run<{ recovery_codes: string[] }>("POST", "/v1/me/mfa/confirm", { code: String(form.get("code") ?? "").trim() });
    if (r) {
      setEnrollment(null);
      setRecovery(r.recovery_codes);
    }
  }

  async function disable(form: FormData) {
    if (await run("POST", "/v1/me/mfa/disable", { code: String(form.get("code") ?? "").trim(), password: String(form.get("password") ?? "") })) setRecovery(null);
  }

  async function createToken(form: FormData) {
    const r = await run<{ token: string }>("POST", "/v1/me/tokens", {
      name: String(form.get("name") ?? "").trim(),
      tenant: scope || null,
      permissions: [...picked],
      expires_in_days: Number(form.get("days")) || 30,
    });
    if (r) {
      setCreated(r.token);
      setPicked(new Set());
    }
  }

  // A token can carry only what its owner holds in the chosen scope.
  const held = scope ? (tenantPermissions[scope] ?? []) : globalPermissions;
  const scopes = [...(globalPermissions.length ? [""] : []), ...Object.keys(tenantPermissions)];

  return (
    <div className="space-y-6">
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}

      <Card id="mfa" title={t("mfa")}>
        <p className="mb-3 text-sm">{mfaEnabled ? <Badge tone="ok">{t("mfaOn")}</Badge> : <Badge>{t("mfaOff")}</Badge>}</p>
        {!mfaEnabled && !enrollment && (
          <button type="button" className={primary} onClick={enroll}>
            {t("mfaSetup")}
          </button>
        )}
        {!mfaEnabled && enrollment && (
          <form action={confirm} className="space-y-3 text-sm">
            <p>{t("mfaScan")}</p>
            <p>
              {t("mfaSecret")}: <code className="break-all font-mono text-xs" data-testid="mfa-secret">{enrollment.secret}</code>
            </p>
            <p className="break-all text-xs text-muted">{enrollment.otpauth_uri}</p>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("mfaCode")}</span>
              <input name="code" required inputMode="numeric" autoComplete="one-time-code" className={`w-40 ${field}`} />
            </label>
            <button type="submit" className={primary}>
              {t("mfaConfirm")}
            </button>
          </form>
        )}
        {recovery && (
          <div role="status" className="mt-3 rounded-md border border-ok p-3 text-sm">
            <p className="mb-1 font-medium">{t("recoveryOnce")}</p>
            <ul className="font-mono text-xs" data-testid="recovery-codes">
              {recovery.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
        )}
        {mfaEnabled && (
          <form action={disable} className="mt-3 flex flex-wrap items-end gap-3 text-sm">
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("password")}</span>
              <input name="password" type="password" required autoComplete="current-password" className={`w-48 ${field}`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("mfaCode")}</span>
              <input name="code" required inputMode="numeric" autoComplete="one-time-code" className={`w-40 ${field}`} />
            </label>
            <button type="submit" className={`${button} text-danger`}>
              {t("mfaDisable")}
            </button>
          </form>
        )}
      </Card>

      <Card id="sessions" title={t("sessions")}>
        <Table caption={t("sessions")} head={[t("device"), t("address"), t("started"), t("lastSeen"), ""]} empty={t("noSessions")}>
          {sessions.map((s) => (
            <Row key={s.id}>
              <Cell>
                <span className="break-all">{s.user_agent ?? "—"}</span> {s.current && <Badge tone="ok">{t("thisSession")}</Badge>}
              </Cell>
              <Cell>{s.ip ?? "—"}</Cell>
              <Cell>{s.created}</Cell>
              <Cell>{s.seen}</Cell>
              <Cell>
                {!s.current && (
                  <button type="button" className={button} onClick={() => run("DELETE", `/v1/me/sessions/${encodeURIComponent(s.id)}`)}>
                    {t("revoke")}
                  </button>
                )}
              </Cell>
            </Row>
          ))}
        </Table>
      </Card>

      <Card id="tokens" title={t("tokens")}>
        {tokens === null ? (
          <p className="text-sm text-muted">{t("tokensDenied")}</p>
        ) : (
          <div className="space-y-4">
            <form action={createToken} className="space-y-3 text-sm">
              <div className="flex flex-wrap items-end gap-3">
                <label className="flex flex-col gap-1">
                  <span className="text-muted">{t("tokenName")}</span>
                  <input name="name" required className={`w-44 ${field}`} />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-muted">{t("tokenScope")}</span>
                  <select
                    value={scope}
                    onChange={(e) => {
                      setScope(e.target.value);
                      setPicked(new Set());
                    }}
                    className={field}
                  >
                    {scopes.map((s) => (
                      <option key={s} value={s}>
                        {s || t("global")}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-muted">{t("tokenDays")}</span>
                  <input name="days" type="number" min={1} max={365} defaultValue={30} className={`w-24 ${field}`} />
                </label>
              </div>
              <fieldset>
                <legend className="mb-1 text-muted">{t("tokenPermissions")}</legend>
                <div className="flex flex-wrap gap-x-4 gap-y-1">
                  {held.map((p) => (
                    <label key={p} className="flex items-center gap-1 font-mono text-xs">
                      <input
                        type="checkbox"
                        checked={picked.has(p)}
                        onChange={() => {
                          const next = new Set(picked);
                          if (!next.delete(p)) next.add(p);
                          setPicked(next);
                        }}
                      />
                      {p}
                    </label>
                  ))}
                </div>
              </fieldset>
              <button type="submit" disabled={picked.size === 0} className={`${primary} disabled:opacity-50`}>
                {t("tokenCreate")}
              </button>
            </form>
            {created && (
              <div role="status" className="rounded-md border border-ok p-3 text-sm">
                <p className="mb-1 font-medium">{t("tokenOnce")}</p>
                <code className="break-all font-mono text-xs" data-testid="new-token">
                  {created}
                </code>
              </div>
            )}
            <Table caption={t("tokens")} head={[t("tokenName"), t("tokenScope"), t("tokenPermissions"), t("expires"), t("lastUsed"), ""]} empty={t("noTokens")}>
              {tokens.map((k) => (
                <Row key={k.id}>
                  <Cell>{k.name}</Cell>
                  <Cell>{k.tenant ?? t("global")}</Cell>
                  <Cell mono>{k.permissions.join(", ")}</Cell>
                  <Cell>{k.expires}</Cell>
                  <Cell>{k.used ?? "—"}</Cell>
                  <Cell>
                    <button type="button" className={`${button} text-danger`} onClick={() => run("DELETE", `/v1/me/tokens/${encodeURIComponent(k.id)}`)}>
                      {t("revoke")}
                    </button>
                  </Cell>
                </Row>
              ))}
            </Table>
          </div>
        )}
      </Card>
    </div>
  );
}
