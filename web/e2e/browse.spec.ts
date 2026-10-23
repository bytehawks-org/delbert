import { expect, test } from "@playwright/test";

// Read-only views (M1). Prepares data through the Core's API (set CORE_URL, and NODE_EXTRA_CA_CERTS for its CA).
const CORE = process.env.CORE_URL;
const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password" };

async function api(path: string, method: string, body?: unknown, token?: string) {
  const res = await fetch(`${CORE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as Record<string, any> };
}

const policy = (tenant: string, greeting: string) =>
  `apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: web-base, tenant: ${tenant} }\nspec:\n  target: { groups: [web] }\n  resources:\n    - id: motd\n      copy: { content: "${greeting}\\n", dest: /etc/motd, mode: "0644" }\n`;

async function signIn(page: import("@playwright/test").Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByLabel(/username/i).fill(username);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
}

test.skip(!CORE, "CORE_URL is not set");

test("an administrator browses tenants, policies with their versions, agents, proxies and the audit trail", async ({ page }) => {
  const tenant = `t${Date.now()}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  expect((await api("/v1/tenants", "POST", { name: tenant }, admin)).status).toBe(201);
  for (const g of ["first", "second"]) expect((await api(`/v1/tenants/${tenant}/policies`, "POST", { yaml: policy(tenant, g) }, admin)).status).toBe(201);

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.getByRole("navigation", { name: /main/i }).getByRole("link", { name: "Tenants" }).click();
  await page.getByRole("link", { name: tenant }).click();
  await expect(page.getByRole("heading", { name: tenant, level: 1 })).toBeVisible();
  await expect(page.getByText("Names only")).toBeVisible();

  await page.getByRole("link", { name: "web-base" }).click();
  await expect(page.getByTestId("policy-yaml")).toContainText("second");
  await page.getByRole("link", { name: "v1" }).click();
  await expect(page.getByTestId("policy-yaml")).toContainText("first");

  await page.goto("/agents");
  await expect(page.getByRole("heading", { name: "Agents", level: 1 })).toBeVisible();
  await page.goto("/proxies");
  await expect(page.getByRole("heading", { name: "Proxies", level: 1 })).toBeVisible();

  await page.goto(`/audit?tenant=${tenant}`);
  await expect(page.getByText("intact")).toBeVisible();
  await expect(page.getByRole("cell", { name: "policy.create" }).first()).toBeVisible();
  await page.goto(`/audit?tenant=${tenant}&action=nothing.here`);
  await expect(page.getByText("No events match.")).toBeVisible();
});

test("a tenant-scoped viewer sees only its tenant and gets notices where its roles do not reach", async ({ page }) => {
  const tenant = `s${Date.now()}`;
  const other = `o${Date.now()}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  for (const t of [tenant, other]) await api("/v1/tenants", "POST", { name: t }, admin);
  const name = `view-${Date.now()}`;
  const password = "a-long-enough-password";
  expect((await api("/v1/users", "POST", { username: name, password, assignments: [{ role: "viewer", tenant }] }, admin)).status).toBe(201);

  await signIn(page, name, password);
  await page.goto("/tenants");
  await expect(page.getByRole("link", { name: tenant })).toBeVisible();
  await expect(page.getByRole("link", { name: other })).toHaveCount(0);
  await page.goto("/audit");
  await expect(page.getByRole("status")).toContainText(/do not cover/i);
  const unknown = await page.goto(`/tenants/${other}`);
  expect([403, 404]).toContain(unknown?.status());
});
