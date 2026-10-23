"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useEffect, useMemo, useState } from "react";
import { diffLines } from "@/lib/diff";
import { callCore } from "@/lib/mutate";

type Check = { state: "idle" | "checking" } | { state: "ok"; name: string; next: number; approval: boolean } | { state: "bad"; error: string };

/** YAML editor: every pause in typing asks the Core to validate (nothing is stored), and the change is shown against `base`. */
export function PolicyEditor({ tenant, initial, base, baseLabel }: { tenant: string; initial: string; base: string | null; baseLabel: string }) {
  const t = useTranslations("editor");
  const router = useRouter();
  const [yaml, setYaml] = useState(initial);
  const [check, setCheck] = useState<Check>({ state: "idle" });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (!yaml.trim()) return setCheck({ state: "bad", error: t("empty") });
    setCheck({ state: "checking" });
    const handle = setTimeout(async () => {
      const r = await callCore<{ name: string; next_version: number; approval_required: boolean }>("POST", `/v1/tenants/${encodeURIComponent(tenant)}/policies/validate`, { yaml });
      setCheck(r.ok && r.data ? { state: "ok", name: r.data.name, next: r.data.next_version, approval: r.data.approval_required } : { state: "bad", error: r.error ?? "?" });
    }, 500);
    return () => clearTimeout(handle);
  }, [yaml, tenant, t]);

  const changes = useMemo(() => (base === null ? null : diffLines(base, yaml)), [base, yaml]);
  const changed = changes ? changes.some((l) => l.kind !== "same") : true;

  async function save() {
    setSaving(true);
    setSaveError(null);
    const r = await callCore<{ name: string }>("POST", `/v1/tenants/${encodeURIComponent(tenant)}/policies`, { yaml });
    if (r.ok && r.data) router.push(`/tenants/${encodeURIComponent(tenant)}/policies/${encodeURIComponent(r.data.name)}`);
    else {
      setSaveError(r.error ?? "?");
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      <label className="block">
        <span className="mb-1 block text-sm text-muted">{t("source")}</span>
        <textarea
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          spellCheck={false}
          rows={22}
          data-testid="policy-input"
          className="w-full rounded-md border border-border bg-surface p-3 font-mono text-xs leading-relaxed"
        />
      </label>
      <div aria-live="polite" className="min-h-6 text-sm" data-testid="policy-check">
        {check.state === "checking" && <span className="text-muted">{t("checking")}</span>}
        {check.state === "ok" && (
          <span className="text-ok">
            ✓ {t("valid", { name: check.name, version: check.next })} {check.approval ? t("draftNote") : t("liveNote")}
          </span>
        )}
        {check.state === "bad" && (
          <span role="alert" className="text-danger">
            ✗ {check.error}
          </span>
        )}
      </div>
      {saveError && (
        <p role="alert" className="text-sm text-danger">
          {saveError}
        </p>
      )}
      <button
        type="button"
        onClick={save}
        disabled={check.state !== "ok" || saving || !changed}
        className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg disabled:opacity-50"
      >
        {saving ? t("saving") : t("save")}
      </button>
      {changes && (
        <section aria-label={t("changes", { base: baseLabel })}>
          <h2 className="mb-2 text-lg font-medium">{t("changes", { base: baseLabel })}</h2>
          {!changed ? (
            <p className="text-sm text-muted">{t("noChanges")}</p>
          ) : (
            <pre className="max-h-96 overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-xs leading-relaxed" data-testid="policy-diff">
              {changes.map((l, i) => (
                <div key={i} className={l.kind === "add" ? "text-ok" : l.kind === "del" ? "text-danger" : "text-muted"}>
                  {l.kind === "add" ? "+ " : l.kind === "del" ? "- " : "  "}
                  {l.text}
                </div>
              ))}
            </pre>
          )}
        </section>
      )}
    </div>
  );
}
