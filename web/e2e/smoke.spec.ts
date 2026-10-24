import { expect, test } from "@playwright/test";

// The administrator created by the e2e stack (compose.e2e.yaml: DELBERT_BOOTSTRAP_ADMIN_PASSWORD).
const USER = process.env.E2E_ADMIN_USER ?? "admin";
const PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password";

test("pages that need a session send the browser to the login page, with strict security headers", async ({ page }) => {
  const response = await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  const headers = response?.headers() ?? {};
  expect(headers["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["cache-control"]).toContain("no-store");
});

test("login fails with a wrong password and works with the right one, then logs out", async ({ page, context }) => {
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: /sign in|accedi/i })).toBeVisible();

  await page.getByLabel(/username|nome utente/i).fill(USER);
  await page.getByLabel(/password/i).fill("not-the-password");
  await page.getByRole("button", { name: /sign in|accedi/i }).click();
  await expect(page.locator("main [role=alert]")).toContainText(/invalid|non validi/i);
  await expect(page).toHaveURL(/\/login$/);

  await page.getByLabel(/password/i).fill(PASSWORD);
  await page.getByRole("button", { name: /sign in|accedi/i }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("signed-in-as")).toContainText(USER);
  await expect(page.getByTestId("tenant-count")).toBeVisible();

  // The Core's token is not reachable from JavaScript: the cookie is HttpOnly and not the raw token.
  const cookie = (await context.cookies()).find((c) => c.name === "delbert_web");
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Strict");
  expect(await page.evaluate(() => document.cookie)).not.toContain("delbert_web");

  await page.getByRole("button", { name: /sign out|esci/i }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
});

test("the language and theme can be switched, and the choice is kept", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel(/language|lingua/i).selectOption("it");
  await expect(page.getByRole("heading", { name: "Accedi" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "it");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Accedi" })).toBeVisible();

  await page.getByLabel(/tema/i).selectOption("dark");
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator("html")).toHaveClass(/dark/);
});

test("state-changing requests from another origin are refused", async ({ request }) => {
  const res = await request.post("/api/auth/login", { data: { username: USER, password: PASSWORD }, headers: { origin: "https://evil.example" } });
  expect(res.status()).toBe(403);
});

test("a login submitted before the page is interactive never puts the password in the URL", async ({ browser }) => {
  // Without JavaScript the form behaves as it does before hydration: it must do nothing.
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto("/login");
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill("secret-that-must-stay-out-of-the-url");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeDisabled();
  await page.locator("#password").press("Enter");
  await page.waitForTimeout(500);
  expect(page.url()).not.toContain("secret-that-must-stay-out-of-the-url");
  expect(page.url()).not.toContain("password=");
  await context.close();
});
