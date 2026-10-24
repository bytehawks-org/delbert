"use client";

import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useRef, useState } from "react";
import { putFile } from "@/lib/mutate";

/** Uploads a file as an artifact (a new version when the name exists); without a tenant, as a global one. The Core caps the size. */
export function ArtifactUpload({ tenant }: { tenant?: string }) {
  const t = useTranslations("artifacts");
  const router = useRouter();
  const form = useRef<HTMLFormElement>(null);
  const [state, setState] = useState<{ busy: boolean; error?: string }>({ busy: false });

  async function upload(data: FormData) {
    const file = data.get("file");
    if (!(file instanceof File) || file.size === 0) return;
    const name = String(data.get("name") || file.name);
    setState({ busy: true });
    const base = tenant ? `/v1/tenants/${encodeURIComponent(tenant)}/artifacts` : "/v1/globals/artifacts";
    const r = await putFile(`${base}/${encodeURIComponent(name)}`, file);
    setState({ busy: false, error: r.ok ? undefined : r.error });
    if (r.ok) {
      form.current?.reset();
      router.refresh();
    }
  }

  return (
    <form ref={form} action={upload} className="mb-3 flex flex-wrap items-end gap-3 text-sm">
      <label className="flex flex-col gap-1">
        <span className="text-muted">{t("file")}</span>
        <input name="file" type="file" required />
      </label>
      <label className="flex flex-col gap-1">
        <span className="text-muted">{t("nameOptional")}</span>
        <input name="name" pattern="[A-Za-z0-9._-]+" className="w-40 rounded-md border border-border bg-surface px-2 py-1.5" />
      </label>
      <button type="submit" disabled={state.busy} className="rounded-md bg-action px-3 py-1.5 font-medium text-action-fg disabled:opacity-50">
        {state.busy ? t("uploading") : t("upload")}
      </button>
      {state.error && (
        <p role="alert" className="w-full text-danger">
          {state.error}
        </p>
      )}
    </form>
  );
}
