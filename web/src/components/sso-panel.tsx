"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { Badge, Cell, Row, Table } from "@/components/ui";
import { callCore } from "@/lib/mutate";

type Mapping = { group: string; role: string; tenant?: string | null };
type Provider = {
  name: string;
  display_name: string;
  issuer: string;
  client_id: string;
  has_client_secret: boolean;
  scopes: string[];
  groups_claim: string;
  require_mapping: boolean;
  enabled: boolean;
  redirect_uri?: string | null;
  mappings: Mapping[];
};

const field = "rounded-md border border-border bg-surface px-2 py-1.5";
const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface";
const empty: Provider = { name: "", display_name: "", issuer: "", client_id: "", has_client_secret: false, scopes: ["openid", "profile", "email"], groups_claim: "groups", require_mapping: true, enabled: true, mappings: [] };

/** OIDC providers and the mapping from identity-provider groups to (role, scope). The client secret is write-only. */
export function SsoPanel({ providers, roles, tenants, canWrite }: { providers: Provider[]; roles: string[]; tenants: string[]; canWrite: boolean }) {
  const t = useTranslations("sso");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Provider | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [secret, setSecret] = useState("");
  const [results, setResults] = useState<Record<string, { ok: boolean; detail: string }>>({});

  const set = (patch: Partial<Provider>) => setDraft((d) => (d ? { ...d, ...patch } : d));
  const setMapping = (i: number, patch: Partial<Mapping>) => set({ mappings: draft!.mappings.map((m, j) => (j === i ? { ...m, ...patch } : m)) });

  function open(p: Provider, fresh: boolean) {
    setDraft(structuredClone(p));
    setIsNew(fresh);
    setSecret("");
    setError(null);
  }

  async function save() {
    if (!draft) return;
    setError(null);
    const body = {
      name: draft.name.trim(),
      display_name: draft.display_name.trim(),
      issuer: draft.issuer.trim(),
      client_id: draft.client_id.trim(),
      client_secret: secret || null, // absent on update keeps the stored secret
      scopes: draft.scopes,
      groups_claim: draft.groups_claim.trim() || "groups",
      require_mapping: draft.require_mapping,
      enabled: draft.enabled,
      mappings: draft.mappings.filter((m) => m.group.trim() && m.role).map((m) => ({ group: m.group.trim(), role: m.role, tenant: m.tenant || null })),
    };
    const r = isNew ? await callCore("POST", "/v1/sso/providers", body) : await callCore("PUT", `/v1/sso/providers/${encodeURIComponent(draft.name)}`, body);
    if (!r.ok) return setError(r.error ?? "?");
    setDraft(null);
    router.refresh();
  }

  async function remove(name: string) {
    if (window.prompt(t("confirmDelete", { name })) !== name) return;
    const r = await callCore("DELETE", `/v1/sso/providers/${encodeURIComponent(name)}`);
    if (!r.ok) return setError(r.error ?? "?");
    router.refresh();
  }

  async function test(name: string) {
    const r = await callCore<{ ok: boolean; detail: string }>("POST", `/v1/sso/providers/${encodeURIComponent(name)}/test`);
    setResults({ ...results, [name]: r.ok && r.data ? r.data : { ok: false, detail: r.error ?? "?" } });
  }

  return (
    <div className="space-y-6">
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
      <Table caption={t("title")} head={[t("name"), t("issuer"), t("state"), t("mappings"), ""]} empty={t("none")}>
        {providers.map((p) => (
          <Row key={p.name}>
            <Cell>
              {p.display_name} <span className="text-muted">({p.name})</span>
              {p.redirect_uri && <p className="break-all text-xs text-muted">{t("redirectUri")}: {p.redirect_uri}</p>}
            </Cell>
            <Cell>{p.issuer}</Cell>
            <Cell>{p.enabled ? <Badge tone="ok">{t("enabled")}</Badge> : <Badge>{t("disabled")}</Badge>}</Cell>
            <Cell>{p.mappings.length}</Cell>
            <Cell>
              <div className="flex flex-wrap items-center gap-2">
                {canWrite && (
                  <>
                    <button type="button" className={button} onClick={() => open(p, false)}>
                      {t("edit")}
                    </button>
                    <button type="button" className={button} onClick={() => test(p.name)}>
                      {t("test")}
                    </button>
                    <button type="button" className={`${button} text-danger`} onClick={() => remove(p.name)}>
                      {t("delete")}
                    </button>
                  </>
                )}
                {results[p.name] && (
                  <span role="status" className={`text-xs ${results[p.name]!.ok ? "text-ok" : "text-danger"}`}>
                    {results[p.name]!.ok ? "✓" : "✗"} {results[p.name]!.detail}
                  </span>
                )}
              </div>
            </Cell>
          </Row>
        ))}
      </Table>

      {canWrite && !draft && (
        <button type="button" className="rounded-md bg-action px-3 py-1.5 text-sm font-medium text-action-fg" onClick={() => open(empty, true)}>
          {t("add")}
        </button>
      )}

      {canWrite && draft && (
        <section aria-labelledby="provider-form" className="space-y-4 rounded-xl border border-border bg-surface p-5 text-sm">
          <h2 id="provider-form" className="text-lg font-medium">
            {isNew ? t("add") : t("editing", { name: draft.name })}
          </h2>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("slug")}</span>
              <input value={draft.name} disabled={!isNew} onChange={(e) => set({ name: e.target.value })} className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("displayName")}</span>
              <input value={draft.display_name} onChange={(e) => set({ display_name: e.target.value })} className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("issuer")}</span>
              <input value={draft.issuer} onChange={(e) => set({ issuer: e.target.value })} placeholder="https://idp.example.com/realms/main" className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("clientId")}</span>
              <input value={draft.client_id} onChange={(e) => set({ client_id: e.target.value })} className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("clientSecret")}</span>
              <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" placeholder={draft.has_client_secret ? t("secretKept") : ""} className={field} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted">{t("groupsClaim")}</span>
              <input value={draft.groups_claim} onChange={(e) => set({ groups_claim: e.target.value })} className={field} />
            </label>
            <label className="flex flex-col gap-1 md:col-span-2">
              <span className="text-muted">{t("scopes")}</span>
              <input value={draft.scopes.join(" ")} onChange={(e) => set({ scopes: e.target.value.split(/\s+/).filter(Boolean) })} className={field} />
            </label>
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-2">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={draft.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              {t("enabled")}
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={draft.require_mapping} onChange={(e) => set({ require_mapping: e.target.checked })} />
              {t("requireMapping")}
            </label>
          </div>

          <fieldset className="space-y-2">
            <legend className="mb-1 font-medium">{t("mappings")}</legend>
            <p className="text-xs text-muted">{t("mappingsHelp")}</p>
            {draft.mappings.map((m, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <input aria-label={t("group")} value={m.group} onChange={(e) => setMapping(i, { group: e.target.value })} placeholder={t("group")} className={`w-52 ${field}`} />
                <select aria-label={t("role")} value={m.role} onChange={(e) => setMapping(i, { role: e.target.value })} className={field}>
                  <option value="">{t("role")}</option>
                  {roles.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <select aria-label={t("scope")} value={m.tenant ?? ""} onChange={(e) => setMapping(i, { tenant: e.target.value || null })} className={field}>
                  <option value="">{t("global")}</option>
                  {tenants.map((x) => (
                    <option key={x} value={x}>
                      {x}
                    </option>
                  ))}
                </select>
                <button type="button" className={button} onClick={() => set({ mappings: draft.mappings.filter((_, j) => j !== i) })}>
                  {t("removeMapping")}
                </button>
              </div>
            ))}
            <button type="button" className={button} onClick={() => set({ mappings: [...draft.mappings, { group: "", role: "", tenant: null }] })}>
              {t("addMapping")}
            </button>
          </fieldset>

          <div className="flex gap-2">
            <button type="button" onClick={save} disabled={!draft.name.trim() || !draft.issuer.trim() || !draft.client_id.trim()} className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg disabled:opacity-50">
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
