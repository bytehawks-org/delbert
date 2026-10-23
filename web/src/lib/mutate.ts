/** Calls the Core through the server (`/api/core/...`), which adds the session. Browser side. */
export async function callCore<T = unknown>(method: "POST" | "PUT" | "DELETE", path: string, body?: unknown): Promise<{ ok: boolean; status: number; data: T | null; error?: string }> {
  const res = await fetch(`/api/core${path}`, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).catch(() => null);
  if (!res) return { ok: false, status: 0, data: null, error: "unreachable" };
  const json = (await res.json().catch(() => null)) as (T & { error?: string }) | null;
  return { ok: res.ok, status: res.status, data: json, error: res.ok ? undefined : (json?.error ?? `HTTP ${res.status}`) };
}

/** Uploads a file's bytes as they are (artifacts). */
export async function putFile(path: string, file: File): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch(`/api/core${path}`, { method: "PUT", headers: { "content-type": "application/octet-stream" }, body: file }).catch(() => null);
  if (!res) return { ok: false, error: "unreachable" };
  if (res.ok) return { ok: true };
  const json = (await res.json().catch(() => null)) as { error?: string } | null;
  return { ok: false, error: json?.error ?? `HTTP ${res.status}` };
}
