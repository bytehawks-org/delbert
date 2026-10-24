import { expect, test } from "@playwright/test";
import { totp } from "./totp";

// Profile (M3): second factor, sessions and API tokens, all through the UI.
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

test("a user sets up a second factor and gets recovery codes, then disables it", async ({ page }) => {
  const id = Date.now();
  const tenant = `p${id}`;
  const user = `mfa-ui-${id}`;
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api("/v1/users", "POST", { username: user, password: PASSWORD, assignments: [{ role: "viewer", tenant }] }, admin);

  await signIn(page, user, PASSWORD);
  await page.getByTestId("signed-in-as").click();
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByText("not set up")).toBeVisible();

  await page.getByRole("button", { name: "Set up" }).click();
  const secret = (await page.getByTestId("mfa-secret").textContent())!.trim();
  await page.getByLabel("Code").fill(totp(secret));
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByTestId("recovery-codes").locator("li")).not.toHaveCount(0);
  await expect(page.getByText("enabled", { exact: true })).toBeVisible();

  // The login now asks for the second factor.
  expect((await api("/v1/auth/login", "POST", { username: user, password: PASSWORD })).json.mfa_required).toBe(true);

  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByLabel("Code").fill(totp(secret, 1)); // the current code was just used (replay protection)
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("not set up")).toBeVisible();
});

test("API tokens are created once, work against the Core and can be revoked; other sessions can be signed out", async ({ page }) => {
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  const name = `ci-${Date.now()}`;

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.goto("/profile");

  // A second session of the same user appears and can be revoked from here.
  await api("/v1/auth/login", "POST", ADMIN);
  await page.reload();
  const others = page.getByRole("row").filter({ hasNot: page.getByText("this session") }).getByRole("button", { name: "Revoke" });
  expect(await others.count()).toBeGreaterThan(0);

  await page.getByLabel("Name").fill(name);
  await page.getByLabel("*", { exact: true }).check();
  await page.getByRole("button", { name: "Create token" }).click();
  const token = (await page.getByTestId("new-token").textContent())!.trim();
  expect((await api("/v1/tenants", "GET", undefined, token)).status).toBe(200);

  const row = page.getByRole("row", { name: new RegExp(name) });
  await row.getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("row", { name: new RegExp(name) })).toHaveCount(0);
  expect((await api("/v1/tenants", "GET", undefined, token)).status).toBe(401);
});
