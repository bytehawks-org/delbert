import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { ADMIN, adminToken, api, signIn } from "./helpers";

// The repository editor (Monaco, served from the site) against a writable git source.
// Needs a source prepared outside the stack, because the stack has no git server:
//   E2E_EDIT_SOURCE=<name of a writable git source of a tenant, already synced, layout of docs/REPOSITORY.md>
//   E2E_EDIT_TENANT=<that tenant>
const SOURCE = process.env.E2E_EDIT_SOURCE;
const TENANT = process.env.E2E_EDIT_TENANT ?? "acme";

test.skip(!process.env.CORE_URL || !SOURCE, "CORE_URL and E2E_EDIT_SOURCE are not set");

test("a file is added, checked as the repository it would make, and committed to a new branch", async ({ page }) => {
  const violations: string[] = [];
  const errors: string[] = [];
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => ((window as any).__csp ??= []).push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  page.on("pageerror", (e) => errors.push(e.message));

  await signIn(page, ADMIN.username, ADMIN.password);
  await page.goto("/content");
  await page.getByRole("row", { name: new RegExp(SOURCE!) }).getByRole("link", { name: "Edit" }).click();
  await expect(page.getByRole("heading", { name: SOURCE! })).toBeVisible();

  // Open a file: Monaco loads from this site and renders.
  await page.getByRole("navigation", { name: "Files" }).getByRole("button", { name: "README.md" }).last().click(); // the root one: folders come first
  await expect(page.locator(".monaco-editor")).toBeVisible({ timeout: 20_000 });
  await expect(page.locator(".monaco-editor .view-lines")).toContainText("Delbert repository");

  // A new policy, typed in the editor. The folder says where it applies.
  await page.getByLabel("Path of a new file").fill("policies/groups/web/baseline.yaml");
  await page.getByRole("button", { name: "Add" }).click();
  const policy = (name: string) => `apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: ${name}, tenant: ${TENANT} }\nspec:\n  resources:\n    - id: motd\n      file: { path: /etc/motd }\n`;
  const setValue = (text: string) => page.evaluate((v) => (window as any).monaco.editor.getEditors()[0].setValue(v), text);
  await expect(page.locator(".monaco-editor")).toBeVisible();

  // Wrong name: the Core says what is wrong with the repository, and commit stays disabled.
  await setValue(policy("other"));
  await expect(page.getByRole("alert").filter({ hasText: "These changes would break the repository" })).toContainText("the file must be called other.yaml");
  await expect(page.getByRole("button", { name: "Commit to a new branch" })).toBeDisabled();

  await setValue(policy("baseline"));
  await expect(page.getByText("The repository stays valid with these changes.")).toBeVisible();
  await page.getByLabel("Commit message").fill("add the baseline for web");
  await page.getByRole("button", { name: "Commit to a new branch" }).click();
  await expect(page.getByRole("status")).toContainText("Pushed to branch delbert/");

  // Audited, with who and where.
  const audit = (await api(`/v1/audit?action=content.commit`, "GET", undefined, await adminToken())).json;
  expect(audit.events[0].details.branch).toMatch(/^delbert\//);

  // The page, apart from Monaco itself, passes the accessibility audit, and the strict CSP was not violated.
  const axe = await new AxeBuilder({ page }).exclude(".monaco-editor").analyze();
  violations.push(...axe.violations.map((v) => `${v.id}: ${v.nodes[0]?.target}`));
  expect(violations).toEqual([]);
  expect(await page.evaluate(() => (window as any).__csp ?? [])).toEqual([]);
  expect(errors).toEqual([]);
});
