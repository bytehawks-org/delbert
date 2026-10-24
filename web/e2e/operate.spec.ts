import { expect, test } from "@playwright/test";

// Operations (M2): policy editor, approval steps, enrollment keys, secrets, artifacts.
const CORE = process.env.CORE_URL;
const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password" };
const PASSWORD = "a-long-enough-password";

async function api(path: string, method: string, body?: unknown, token?: string) {
  const res = await fetch(`${CORE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as Record<string, any> };
}

const yaml = (tenant: string, content: string) =>
  `apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: web-base, tenant: ${tenant} }\nspec:\n  target: { groups: [web] }\n  resources:\n    - id: motd\n      copy: { content: "${content}\\n", dest: /etc/motd, mode: "0644" }\n`;

async function signIn(page: import("@playwright/test").Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByLabel(/username/i).fill(username);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
}

test.skip(!CORE, "CORE_URL is not set");

test("the editor validates while typing, shows the diff and saves a new version", async ({ page }) => {
  const tenant = `e${Date.now()}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api(`/v1/tenants/${tenant}/policies`, "POST", { yaml: yaml(tenant, "first") }, admin);

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.goto(`/tenants/${tenant}/policies/web-base`);
  await page.getByRole("link", { name: /edit as new version/i }).click();

  const input = page.getByTestId("policy-input");
  await input.fill("nonsense: [");
  await expect(page.getByTestId("policy-check")).toContainText("✗");
  await expect(page.getByRole("button", { name: /save as new version/i })).toBeDisabled();

  await input.fill(yaml(tenant, "second"));
  await expect(page.getByTestId("policy-check")).toContainText(/valid: web-base, saving creates version 2/i);
  await expect(page.getByTestId("policy-diff")).toContainText('- ' + '      copy: { content: "first\\n"');
  await page.getByRole("button", { name: /save as new version/i }).click();
  await expect(page).toHaveURL(new RegExp(`/policies/web-base$`));
  await expect(page.getByTestId("policy-yaml")).toContainText("second");
});

test("with four-eyes approval, an author submits and a different user approves and activates", async ({ page, browser }) => {
  const tenant = `a${Date.now()}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api(`/v1/tenants/${tenant}/settings`, "PUT", { approval_required: true }, admin);
  const author = `author-${Date.now()}`;
  const reviewer = `reviewer-${Date.now()}`;
  await api("/v1/users", "POST", { username: author, password: PASSWORD, assignments: [{ role: "operator", tenant }] }, admin);
  await api("/v1/users", "POST", { username: reviewer, password: PASSWORD, assignments: [{ role: "approver", tenant }] }, admin);

  await signIn(page, author, PASSWORD);
  await page.goto(`/tenants/${tenant}/policies/new`);
  await page.getByTestId("policy-input").fill(yaml(tenant, "hello"));
  await expect(page.getByTestId("policy-check")).toContainText(/draft until approved/i);
  await page.getByRole("button", { name: /save as new version/i }).click();
  await expect(page).toHaveURL(/policies\/web-base$/);
  await expect(page.getByRole("button", { name: "Activate" })).toHaveCount(0); // not approved yet
  await page.getByRole("button", { name: /submit for approval/i }).click();
  await expect(page.getByRole("button", { name: /submit for approval/i })).toHaveCount(0);

  // The author cannot review their own change: no approve button, and the Core would refuse anyway.
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);

  const ctx = await browser.newContext();
  const second = await ctx.newPage();
  await signIn(second, reviewer, PASSWORD);
  await second.goto(`/tenants/${tenant}/policies/web-base`);
  await second.getByRole("button", { name: "Approve" }).click();
  await expect(second.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await ctx.close();

  // The author can now activate the approved version.
  await page.reload();
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByText("live", { exact: true }).first()).toBeVisible();
});

test("enrollment keys, secrets and artifacts can be managed", async ({ page }) => {
  const tenant = `k${Date.now()}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await signIn(page, ADMIN.username, ADMIN.password);
  await page.goto(`/tenants/${tenant}`);

  await page.getByLabel(/^groups$/i).fill("web");
  await page.getByRole("button", { name: /create key/i }).click();
  await expect(page.getByTestId("new-key")).not.toBeEmpty();
  await expect(page.getByText("valid", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByText("revoked", { exact: true })).toBeVisible();

  await page.getByRole("region", { name: "Secrets" }).getByLabel(/^name$/i).fill("db-password");
  await page.getByLabel(/^value$/i).fill("s3cret");
  await page.getByRole("button", { name: /save secret/i }).click();
  await expect(page.getByRole("cell", { name: "db-password" })).toBeVisible();
  await expect(page.locator("body")).not.toContainText("s3cret");

  await page.locator('input[type=file]').setInputFiles({ name: "motd.txt", mimeType: "text/plain", buffer: Buffer.from("hello artifact") });
  await page.getByRole("button", { name: /^upload$/i }).click();
  await expect(page.getByRole("cell", { name: "motd.txt" })).toBeVisible();
});

test("the pass-through to the Core only allows what the UI needs", async ({ page }) => {
  await signIn(page, ADMIN.username, ADMIN.password);
  const origin = new URL(page.url()).origin;
  const post = (path: string, from: string) => page.request.post(path, { headers: { origin: from, "content-type": "application/json" }, data: "{}" });
  expect((await post("/api/core/v1/secrets/reseal", origin)).status()).toBe(404);
  expect((await post("/api/core/v1/audit/export", origin)).status()).toBe(404);
  expect((await post("/api/core/v1/tenants/x/enrollment-keys", "https://evil.example.com")).status()).toBe(403);
});
