import { expect, type Page } from "@playwright/test";

export const CORE = process.env.CORE_URL;
export const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password" };

/** Calls the Core directly to prepare data. */
export async function api(path: string, method: string, body?: unknown, token?: string) {
  const res = await fetch(`${CORE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

export async function adminToken(): Promise<string> {
  return (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
}

export async function signIn(page: Page, username = ADMIN.username, password = ADMIN.password) {
  await page.goto("/login");
  await page.getByLabel(/username|nome utente/i).fill(username);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in|accedi/i }).click();
  await expect(page).toHaveURL(/\/$/);
}
