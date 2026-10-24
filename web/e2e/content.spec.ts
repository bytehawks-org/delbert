import { expect, test } from "@playwright/test";

// Content sources (M3): the stack has no git server, so a sync of an unreachable repository must fail visibly.
const CORE = process.env.CORE_URL;
const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password" };
const PASSWORD = "a-long-enough-password";

async function api(path: string, method: string, body?: unknown, token?: string) {
  const res = await fetch(`${CORE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

async function signIn(page: import("@playwright/test").Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByLabel(/username/i).fill(username);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
}

test.skip(!CORE, "CORE_URL is not set");

test("a git source is added, a failing sync is reported, the token stays write-only, and it can be removed", async ({ page }) => {
  const id = Date.now();
  const name = `repo-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.getByRole("link", { name: "Content", exact: true }).click();
  await page.getByRole("button", { name: "Add source" }).click();
  const form = page.getByRole("region", { name: "Add source" });
  await form.getByLabel("Name", { exact: true }).fill(name);
  await form.getByLabel("Repository URL (https)").fill("https://git.invalid/org/policies.git");
  await form.getByLabel(/Access token/).fill("t0ken-value");
  await form.getByRole("button", { name: "Save source" }).click();

  const row = page.getByRole("row", { name: new RegExp(name) });
  await expect(row).toContainText("platform");
  await expect(page.locator("body")).not.toContainText("t0ken-value");
  expect((await api(`/v1/content/sources/${name}`, "GET", undefined, admin)).json.has_token).toBe(true);

  await row.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "git fetch failed" })).toBeVisible({ timeout: 25_000 });
  await expect(page.getByRole("row", { name: new RegExp(name) })).toContainText("failing");

  // The history page opens even when nothing was applied.
  await page.getByRole("link", { name }).click();
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await page.goBack();

  page.once("dialog", (d) => d.accept(name));
  await page.getByRole("row", { name: new RegExp(name) }).getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toHaveCount(0);
});

test("a tenant viewer sees its tenant's sources read-only", async ({ page }) => {
  const id = Date.now();
  const tenant = `v${id}`;
  const name = `own-${id}`;
  const user = `reader-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  expect((await api("/v1/content/sources", "POST", { name, kind: "git", location: "https://git.invalid/org/p.git", tenant }, admin)).status).toBe(201);
  expect((await api("/v1/content/sources", "POST", { name: `other-${id}`, kind: "git", location: "https://git.invalid/org/q.git" }, admin)).status).toBe(201);
  await api("/v1/users", "POST", { username: user, password: PASSWORD, assignments: [{ role: "viewer", tenant }] }, admin);

  await signIn(page, user, PASSWORD);
  await page.getByRole("link", { name: "Content", exact: true }).click();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toBeVisible();
  await expect(page.getByRole("row", { name: new RegExp(`other-${id}`) })).toHaveCount(0); // platform source: not theirs
  await expect(page.getByRole("button", { name: "Add source" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Sync now" })).toHaveCount(0);
});
