"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useState } from "react";
import { callCore } from "@/lib/mutate";

/** Archives the tenant (the Core refuses while it still has agents). Audit trail and policy history are kept. */
export function TenantArchive({ tenant }: { tenant: string }) {
  const t = useTranslations("tenants");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  async function archive() {
    if (window.prompt(t("confirmArchive", { name: tenant })) !== tenant) return;
    const r = await callCore("DELETE", `/v1/tenants/${encodeURIComponent(tenant)}`);
    if (!r.ok) return setError(r.error ?? "?");
    router.push("/tenants");
    router.refresh();
  }

  return (
    <div className="space-y-2 text-sm">
      <p className="text-muted">{t("archiveHelp")}</p>
      <button type="button" onClick={archive} className="rounded-md border border-danger px-3 py-1.5 text-danger">
        {t("archive")}
      </button>
      {error && (
        <p role="alert" className="text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
