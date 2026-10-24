import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { CORE, adminToken, api, signIn } from "./helpers";

// M4: WCAG 2.1 A/AA checked with axe on every main screen, in light and dark, English and Italian.
test.skip(!CORE, "CORE_URL is not set");

const rules = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

/** Every violation of every screen is collected and reported together. */
const problems: string[] = [];

async function audit(page: import("@playwright/test").Page, where: string) {
  const { violations } = await new AxeBuilder({ page }).withTags(rules).analyze();
  for (const v of violations) problems.push(`${where}: ${v.id} (${v.impact}): ${v.help} — ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
}

test("the login page is accessible in both themes and both languages", async ({ page }) => {
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const locale of ["en", "it"]) {
      await page.context().addCookies([{ name: "NEXT_LOCALE", value: locale, url: process.env.WEB_URL ?? "http://localhost:3000" }]);
      await page.goto("/login");
      await audit(page, `/login (${scheme}, ${locale})`);
    }
  }
  expect(problems).toEqual([]);
});

test("every main screen is accessible, in light and dark", async ({ page }) => {
  test.setTimeout(180_000);
  const id = Date.now();
  const tenant = `a${id}`;
  const admin = await adminToken();
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api(`/v1/tenants/${tenant}/agents`, "POST", { name: "host-1", groups: ["web"] }, admin);
  await api("/v1/content/sources", "POST", { name: `src${id}`, kind: "git", location: "https://git.invalid/o/p.git" }, admin);
  await api(`/v1/tenants/${tenant}/policies`, "POST", { yaml: `apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: base, tenant: ${tenant} }\nspec:\n  target: { groups: [web] }\n  resources:\n    - id: motd\n      copy: { content: "hi\\n", dest: /etc/motd }\n` }, admin);

  const routes = ["/", "/tenants", `/tenants/${tenant}`, `/tenants/${tenant}/policies/base`, `/tenants/${tenant}/policies/new`, `/tenants/${tenant}/agents/host-1`, "/agents", "/proxies", "/users", "/roles", "/sso", "/content", "/shared", `/content/src${id}`, "/audit", "/profile"];
  await signIn(page);
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const route of routes) {
      await page.goto(route);
      await expect(page.locator("main")).toBeVisible();
      await audit(page, `${route} (${scheme})`);
    }
  }
  expect(problems).toEqual([]);
});

test("the keyboard reaches the content: the first Tab stop is the skip link, and it works", async ({ page }) => {
  await signIn(page);
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: /skip to content|vai al contenuto/i });
  await expect(skip).toBeFocused();
  await expect(skip).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#content$/);
  // From there Tab continues inside the page (the navigation is not between the link and the content).
  await page.keyboard.press("Tab");
  const inContent = await page.evaluate(() => !!document.activeElement?.closest("main"));
  expect(inContent).toBe(true);
});
