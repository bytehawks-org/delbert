import { expect, test } from "@playwright/test";
import { CORE, adminToken, api, signIn } from "./helpers";

test.skip(!CORE, "CORE_URL is not set");

test("shared artifacts and variables are inherited, layered and previewed", async ({ page }) => {
  const id = Date.now();
  const tenant = `sh${id}`;
  const file = `app${id}.j2`;
  const admin = await adminToken();
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await api(`/v1/tenants/${tenant}/agents`, "POST", { name: "host-1", groups: ["web"] }, admin);
  const policy = `apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: base, tenant: ${tenant} }\nspec:\n  vars: { port: 80 }\n  resources:\n    - id: conf\n      template: { src: "artifact://${file}", dest: /etc/app.conf }\n`;
  expect((await api(`/v1/tenants/${tenant}/policies`, "POST", { yaml: policy }, admin)).status).toBe(201);

  await signIn(page);

  // The platform uploads a template and a constant; every tenant inherits them.
  await page.goto("/shared");
  await page.locator('input[type="file"]').setInputFiles({ name: file, mimeType: "text/plain", buffer: Buffer.from("env={{ vars.env }} port={{ vars.port }}\n") });
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByRole("row", { name: new RegExp(file) })).toBeVisible();
  const shared = page.getByRole("region", { name: "Shared variables" });
  await shared.getByLabel("Name", { exact: true }).fill(`env${id}`);
  await shared.getByLabel("Value", { exact: true }).fill("prod");
  await shared.getByLabel("Constant").check();
  await shared.getByRole("button", { name: "Save variable" }).click();
  await expect(shared.getByRole("row", { name: new RegExp(`env${id}`) })).toContainText("Constant");

  // In the tenant: the artifact shows as inherited; a tenant variable overrides the policy default.
  await page.goto(`/tenants/${tenant}`);
  await expect(page.getByRole("row", { name: new RegExp(file) })).toContainText("inherited");
  const vars = page.getByRole("region", { name: "Variables" });
  await vars.getByLabel("Name", { exact: true }).fill("port");
  await vars.getByLabel("Value", { exact: true }).fill("8080");
  await vars.getByRole("button", { name: "Save variable" }).click();
  await expect(vars.getByRole("row", { name: /port/ })).toContainText("8080");
  // A lower layer cannot take over a constant: the Core says so.
  await vars.getByLabel("Name", { exact: true }).fill(`env${id}`);
  await vars.getByLabel("Value", { exact: true }).fill("dev");
  await vars.getByRole("button", { name: "Save variable" }).click();
  await expect(vars.getByRole("alert")).toContainText("constant");

  // The agent page shows where each value comes from and the template as it will be rendered.
  await page.goto(`/tenants/${tenant}/agents/host-1`);
  const resolved = page.getByRole("region", { name: "Variables as this agent receives them" });
  await expect(resolved.getByRole("row", { name: /port/ })).toContainText("tenant");
  await expect(resolved.getByRole("row", { name: new RegExp(`env${id}`) })).toContainText("global");
  await expect(page.getByRole("region", { name: "Template preview" })).toContainText("port=8080");
});
