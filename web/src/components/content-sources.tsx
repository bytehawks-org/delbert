"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Badge, Cell, Row, Table, UnifiedDiff } from "@/components/ui";
import { callCore } from "@/lib/mutate";

type Source = {
  name: string;
  kind: string;
  location: string;
  branch: string;
  subdir: string;
  tenant?: string | null;
  poll_secs?: number | null;
  prune: boolean;
  enabled: boolean;
  auth_user?: string | null;
  has_token: boolean;
  last_error?: string | null;
  last_revision?: string | null;
  syncedLabel: string;
};
type SyncResult = { status: string; revision: string; errors: string[]; changes: { tenant: string; kind: string; name: string; change: string; applied: boolean; diff?: string | null }[] };

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";
const blank: Source = { name: "", kind: "git", location: "", branch: "main", subdir: "", tenant: null, poll_secs: null, prune: false, enabled: true, auth_user: null, has_token: false, syncedLabel: "—" };

/** Content sources (a directory or a git repository that owns policies and artifacts) and their manual sync. */
export function ContentSources({ sources, tenants, canWrite, canSync }: { sources: Source[]; tenants: string[]; canWrite: boolean; canSync: boolean }) {
  const t = useTranslations("content");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Source | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [token, setToken] = useState("");
  const [dropToken, setDropToken] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ name: string; sync: SyncResult } | null>(null);

  const set = (patch: Partial<Source>) => setDraft((d) => (d ? { ...d, ...patch } : d));

  function open(s: Source, fresh: boolean) {
    setDraft({ ...s });
    setIsNew(fresh);
    setToken("");
    setDropToken(false);
    setError(null);
  }

  async function save() {
    if (!draft) return;
    setError(null);
    const body = {
      name: draft.name.trim(),
      kind: draft.kind,
      location: draft.location.trim(),
      branch: draft.kind === "git" ? draft.branch.trim() || "main" : null,
      subdir: draft.subdir.trim() || null,
      tenant: draft.tenant || null,
      poll_secs: draft.poll_secs || null,
      prune: draft.prune,
      enabled: draft.enabled,
      auth_user: draft.kind === "git" ? draft.auth_user?.trim() || null : null,
      // absent keeps the stored token, empty removes it
      ...(token ? { auth_token: token } : dropToken ? { auth_token: "" } : {}),
    };
    const r = isNew ? await callCore("POST", "/v1/content/sources", body) : await callCore("PUT", `/v1/content/sources/${encodeURIComponent(draft.name)}`, body);
    if (!r.ok) return setError(r.error ?? "?");
    setDraft(null);
    router.refresh();
  }

  async function sync(name: string) {
    setError(null);
    setBusy(name);
    const r = await callCore<SyncResult>("POST", `/v1/content/sources/${encodeURIComponent(name)}/sync`);
    setBusy(null);
    router.refresh(); // a failed fetch is recorded on the source (last error) as well
    if (!r.ok || !r.data) return setError(r.error ?? "?");
    setResult({ name, sync: r.data });
  }

  async function remove(name: string) {
    if (window.prompt(t("confirmDelete", { name })) !== name) return;
    const r = await callCore("DELETE", `/v1/content/sources/${encodeURIComponent(name)}`);
    if (!r.ok) return setError(r.error ?? "?");
    router.refresh();
  }

  return (
    <div className="space-y-6">
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("name"), t("kind"), t("owner"), t("lastSync"), t("state"), ""]} empty={t("none")}>
        {sources.map((s) => (
          <Row key={s.name}>
            <Cell>
              <Link href={`/content/${encodeURIComponent(s.name)}`} className="font-medium text-accent hover:underline">
                {s.name}
              </Link>
              <p className="break-all text-xs text-muted">{s.location}</p>
            </Cell>
            <Cell>{s.kind}</Cell>
            <Cell>{s.tenant ?? t("platform")}</Cell>
            <Cell>
              {s.syncedLabel}
              {s.last_revision && <p className="font-mono text-xs text-muted">{s.last_revision.slice(0, 12)}</p>}
            </Cell>
            <Cell>
              {!s.enabled ? <Badge>{t("disabled")}</Badge> : s.last_error ? <Badge tone="bad">{t("failing")}</Badge> : <Badge tone="ok">{t("ok")}</Badge>}
              {s.last_error && <p className="mt-1 break-all text-xs text-danger">{s.last_error}</p>}
            </Cell>
            <Cell>
              <div className="flex flex-wrap gap-2">
                {canSync && (
                  <button type="button" className={button} disabled={busy === s.name} onClick={() => sync(s.name)}>
                    {busy === s.name ? t("syncing") : t("syncNow")}
                  </button>
                )}
                {canWrite && (
                  <>
                    <button type="button" className={button} onClick={() => open(s, false)}>
                      {t("edit")}
                    </button>
                    <button type="button" className={`${button} text-danger`} onClick={() => remove(s.name)}>
                      {t("delete")}
                    </button>
                  </>
                )}
              </div>
            </Cell>
          </Row>
        ))}
      </Table>

      {result && (
        <section aria-labelledby="sync-result" className="space-y-2 rounded-lg border border-border bg-surface p-4 text-sm">
          <h2 id="sync-result" className="font-medium">
            {t("syncResult", { name: result.name })}: <Badge tone={result.sync.status === "applied" ? "ok" : result.sync.status === "unchanged" ? "neutral" : "bad"}>{result.sync.status}</Badge>
          </h2>
          {result.sync.errors.length > 0 && (
            <ul className="list-disc pl-5 text-danger">
              {result.sync.errors.map((e, i) => (
                <li key={i} className="break-all">
                  {e}
                </li>
              ))}
            </ul>
          )}
          {result.sync.changes.map((c) => (
            <div key={`${c.tenant}/${c.kind}/${c.name}`} className="space-y-1">
              <p>
                {c.tenant} · {c.kind} <span className="font-mono">{c.name}</span> · <Badge>{c.change}</Badge> {!c.applied && <span className="text-muted">({t("notApplied")})</span>}
              </p>
              {c.diff && <UnifiedDiff text={c.diff} />}
            </div>
          ))}
        </section>
      )}

      {canWrite && !draft && (
        <button type="button" className="rounded-md bg-action px-3 py-1.5 text-sm font-medium text-action-fg" onClick={() => open(blank, true)}>
          {t("add")}
        </button>
      )}

      {canWrite && draft && (
        <section aria-labelledby="source-form" className="space-y-4 rounded-lg border border-border bg-surface p-5 text-sm">
          <h2 id="source-form" className="text-lg font-medium">
            {isNew ? t("add") : t("editing", { name: draft.name })}
          </h2>
          <p className="text-xs text-muted">{t("ownershipHelp")}</p>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("name")}</span>
              <input value={draft.name} disabled={!isNew} onChange={(e) => set({ name: e.target.value })} className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("kind")}</span>
              <select value={draft.kind} disabled={!isNew} onChange={(e) => set({ kind: e.target.value })} className={field}>
                <option value="git">git</option>
                <option value="directory">directory</option>
              </select>
            </label>
            <label className="flex flex-col gap-1 md:col-span-2">
              <span className="text-muted">{draft.kind === "git" ? t("locationGit") : t("locationDir")}</span>
              <input value={draft.location} onChange={(e) => set({ location: e.target.value })} placeholder={draft.kind === "git" ? "https://git.example.com/org/policies.git" : "policies"} className={field} />
            </label>
            {draft.kind === "git" && (
              <>
                <label className="flex flex-col gap-1">
                  <span className="text-muted">{t("branch")}</span>
                  <input value={draft.branch} onChange={(e) => set({ branch: e.target.value })} className={field} />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-muted">{t("authUser")}</span>
                  <input value={draft.auth_user ?? ""} onChange={(e) => set({ auth_user: e.target.value })} className={field} />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-muted">{t("authToken")}</span>
                  <input type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="new-password" placeholder={draft.has_token ? t("tokenKept") : ""} className={field} />
                </label>
                {draft.has_token && !isNew && (
                  <label className="flex items-center gap-2 self-end">
                    <input type="checkbox" checked={dropToken} onChange={(e) => setDropToken(e.target.checked)} />
                    {t("dropToken")}
                  </label>
                )}
              </>
            )}
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("subdir")}</span>
              <input value={draft.subdir} onChange={(e) => set({ subdir: e.target.value })} className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("owner")}</span>
              <select value={draft.tenant ?? ""} disabled={!isNew} onChange={(e) => set({ tenant: e.target.value || null })} className={field}>
                <option value="">{t("platform")}</option>
                {tenants.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("poll")}</span>
              <input type="number" min={30} value={draft.poll_secs ?? ""} onChange={(e) => set({ poll_secs: e.target.value ? Number(e.target.value) : null })} className={`w-32 ${field}`} />
            </label>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-2">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={draft.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              {t("enabled")}
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={draft.prune} onChange={(e) => set({ prune: e.target.checked })} />
              {t("prune")}
            </label>
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={save} disabled={!draft.name.trim() || !draft.location.trim()} className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg disabled:opacity-50">
              {t("save")}
            </button>
            <button type="button" onClick={() => setDraft(null)} className={button}>
              {t("cancel")}
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
