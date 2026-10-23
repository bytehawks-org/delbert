"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { callCore } from "@/lib/mutate";

type Step = "submit" | "approve" | "reject" | "activate" | "rollback";

/** The steps this user can take on one version. The Core decides in the end (four eyes, states); this only hides what cannot work. */
export function VersionActions({ tenant, name, version, steps }: { tenant: string; name: string; version: number; steps: Step[] }) {
  const t = useTranslations("versionActions");
  const router = useRouter();
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (steps.length === 0) return null;

  async function run(step: Step) {
    setBusy(true);
    setError(null);
    const r = await callCore("POST", `/v1/tenants/${encodeURIComponent(tenant)}/policies/${encodeURIComponent(name)}/versions/${version}/${step}`, comment.trim() ? { comment: comment.trim() } : {});
    setBusy(false);
    if (r.ok) {
      setComment("");
      router.refresh();
    } else setError(r.error ?? "?");
  }

  return (
    <div className="space-y-3">
      <label className="block text-sm">
        <span className="text-muted">{t("comment")}</span>
        <input value={comment} onChange={(e) => setComment(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-surface px-2 py-1.5" />
      </label>
      <div className="flex flex-wrap gap-2">
        {steps.map((s) => (
          <button key={s} type="button" disabled={busy} onClick={() => run(s)} className={`rounded-md border px-3 py-1.5 text-sm disabled:opacity-50 ${s === "reject" ? "border-danger text-danger" : "border-border"}`}>
            {t(s)}
          </button>
        ))}
      </div>
      {error && (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
