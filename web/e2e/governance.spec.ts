import { expect, test } from "@playwright/test";

// Governance (M3): users, roles and the permission matrix.
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

test("an administrator builds a custom role from the matrix and assigns it to a new user", async ({ page }) => {
  const id = Date.now();
  const tenant = `g${id}`;
  const role = `agent-ops-${id}`;
  const user = `ops-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.getByRole("link", { name: "Roles" }).click();

  // Tenant roles cannot hold platform-wide permissions: those cells are disabled.
  await page.getByLabel("Name").fill(role);
  await expect(page.getByLabel("users:write")).toBeDisabled();
  await page.getByLabel("agents:read", { exact: true }).check();
  await page.getByLabel("agents:*", { exact: true }).check(); // "all" replaces the single cells of the row
  await page.getByLabel("secrets:read", { exact: true }).check();
  await page.getByRole("button", { name: "Save role" }).click();
  const row = page.getByRole("row", { name: new RegExp(role) });
  await expect(row).toContainText("agents:*");
  await expect(row).toContainText("secrets:read");
  await expect(row).not.toContainText("agents:read");

  // The built-in roles are read-only.
  await expect(page.getByRole("row", { name: /operator/ }).getByRole("button", { name: "Edit" })).toHaveCount(0);

  // New user with that role in one tenant.
  await page.getByRole("link", { name: "Users" }).click();
  await page.getByLabel("Username").fill(user);
  await page.getByLabel(/Password/).fill(PASSWORD);
  await page.getByLabel("Role").first().selectOption(role);
  await page.getByLabel("Scope").first().selectOption(tenant);
  await page.getByRole("button", { name: "Create user" }).click();
  const urow = page.getByRole("row", { name: new RegExp(user) });
  await expect(urow).toContainText(`${role} @ ${tenant}`);

  // The new user can read the tenant's secrets list but sees no governance menu.
  expect((await api(`/v1/tenants/${tenant}/secrets`, "GET", undefined, (await api("/v1/auth/login", "POST", { username: user, password: PASSWORD })).json.token)).status).toBe(200);

  // Deactivation locks the account out; deleting asks for the name.
  await urow.getByRole("button", { name: "Deactivate" }).click();
  await expect(urow).toContainText("inactive");
  expect((await api("/v1/auth/login", "POST", { username: user, password: PASSWORD })).status).toBe(401);
  page.once("dialog", (d) => d.accept(user));
  await urow.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("row", { name: new RegExp(user) })).toHaveCount(0);
});

test("a tenant-scoped user does not get the Users and Roles sections", async ({ page }) => {
  const id = Date.now();
  const tenant = `s${id}`;
  const user = `viewer-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api("/v1/users", "POST", { username: user, password: PASSWORD, assignments: [{ role: "viewer", tenant }] }, admin);

  await signIn(page, user, PASSWORD);
  await expect(page.getByRole("link", { name: "Tenants" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Users" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Roles" })).toHaveCount(0);

  // The pass-through exposes only what the UI uses, and the Core still refuses what the role lacks.
  await page.goto("/users");
  await expect(page.getByText("Your role does not cover user management.")).toBeVisible();
});

test("tenant access: roles are assigned and removed on the tenant page, and approval is switched on", async ({ page }) => {
  const id = Date.now();
  const tenant = `t${id}`;
  const user = `member-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api("/v1/users", "POST", { username: user, password: PASSWORD, assignments: [] }, admin);

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.goto(`/tenants/${tenant}`);
  const access = page.getByRole("region", { name: "Access and approval" });

  await access.getByRole("button", { name: "Assign roles to a user" }).click();
  await access.getByLabel("Username").fill(user);
  await access.getByLabel("operator", { exact: true }).check();
  await access.getByRole("button", { name: "Save" }).click();
  const row = access.getByRole("row", { name: new RegExp(user) });
  await expect(row).toContainText("operator");
  // Only tenant-assignable roles are offered.
  await expect(access.getByLabel("platform-admin")).toHaveCount(0);

  await access.getByLabel("Four-eyes approval").check();
  await expect.poll(async () => (await api(`/v1/tenants/${tenant}/settings`, "GET", undefined, admin)).json.approval_required).toBe(true);

  page.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "Remove" }).click();
  await expect(access.getByRole("row", { name: new RegExp(user) })).toHaveCount(0);
});
