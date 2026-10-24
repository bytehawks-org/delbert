import { expect, test } from "@playwright/test";

// Management (M2 leftovers): tenants, agents and proxies from the console.
const CORE = process.env.CORE_URL;
const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password" };

async function api(path: string, method: string, body?: unknown, token?: string) {
  const res = await fetch(`${CORE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

async function signIn(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.getByLabel(/username/i).fill(ADMIN.username);
  await page.getByLabel(/password/i).fill(ADMIN.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/);
}

test.skip(!CORE, "CORE_URL is not set");

test("a tenant is created, gets an agent, and is archived only once it has none", async ({ page }) => {
  const tenant = `m${Date.now()}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;

  await signIn(page);
  await page.goto("/tenants");
  await page.getByLabel("New tenant").fill(tenant);
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/tenants/${tenant}$`));

  // Agent: add, change its groups, see the Core refuse the archive while it exists.
  const agents = page.getByRole("region", { name: "Agents" });
  await agents.getByText("Add or manage agents").click();
  await agents.getByLabel("Name", { exact: true }).fill("host-1");
  await agents.getByLabel("Groups (comma separated)", { exact: true }).fill("web");
  await agents.getByRole("button", { name: "Add agent" }).click();
  const groups = page.getByLabel("Groups of host-1");
  await expect(groups).toHaveValue("web");
  await groups.fill("web, db");
  await page.getByRole("button", { name: "Save groups" }).click();
  await expect.poll(async () => (await api(`/v1/tenants/${tenant}/agents`, "GET", undefined, admin)).json[0]?.groups).toEqual(["web", "db"]);

  page.once("dialog", (d) => d.accept(tenant));
  await page.getByRole("button", { name: "Archive tenant" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "still has 1 agent" })).toBeVisible();

  page.once("dialog", (d) => d.accept("host-1"));
  await agents.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByLabel("Groups of host-1")).toHaveCount(0);

  page.once("dialog", (d) => d.accept(tenant));
  await page.getByRole("button", { name: "Archive tenant" }).click();
  await expect(page).toHaveURL(/\/tenants$/);
  await expect(page.getByRole("link", { name: tenant })).toHaveCount(0);
  expect((await api(`/v1/tenants/${tenant}/agents`, "GET", undefined, admin)).status).toBe(404);
});

test("a proxy is registered with a one-time key and removed", async ({ page }) => {
  const name = `site${Date.now()}`;
  await signIn(page);
  await page.goto("/proxies");
  await page.getByLabel("Name", { exact: true }).fill(name);
  await page.getByLabel("DNS names (comma separated)").fill(`${name}.example.com`);
  await page.getByRole("button", { name: "Register proxy" }).click();
  await expect(page.getByTestId("proxy-key")).not.toBeEmpty();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toContainText("waiting for enrollment");

  await page.getByRole("button", { name: `Configuration of proxy ${name}` }).click();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toContainText(`${name}.example.com`);

  page.once("dialog", (d) => d.accept(name));
  await page.getByRole("button", { name: `Delete proxy ${name}` }).click();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toHaveCount(0);
});

test("a tenant-scoped administrator gets agent management but no tenant creation or archive", async ({ page }) => {
  const id = Date.now();
  const tenant = `n${id}`;
  const user = `tadmin-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api("/v1/users", "POST", { username: user, password: "a-long-enough-password", assignments: [{ role: "tenant-admin", tenant }] }, admin);

  await page.goto("/login");
  await page.getByLabel(/username/i).fill(user);
  await page.getByLabel(/password/i).fill("a-long-enough-password");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/$/); // signed in before navigating on
  await page.goto("/tenants");
  await expect(page.getByLabel("New tenant")).toHaveCount(0);
  await page.goto(`/tenants/${tenant}`);
  await expect(page.getByText("Add or manage agents")).toBeVisible();
  await expect(page.getByRole("button", { name: "Archive tenant" })).toHaveCount(0);
});
