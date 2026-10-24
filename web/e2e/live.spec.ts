import { expect, test } from "@playwright/test";
import { CORE, adminToken, api, signIn } from "./helpers";

// M4: the dashboard shows real health and follows changes without a reload.
test.skip(!CORE, "CORE_URL is not set");

test("the dashboard updates by itself when something changes, and lists what needs attention", async ({ page }) => {
  const id = Date.now();
  const tenant = `d${id}`;
  const admin = await adminToken();

  await signIn(page);
  await expect(page.getByTestId("live-state")).toHaveAttribute("data-state", "live", { timeout: 10_000 });
  const before = Number(await page.getByTestId("tenant-count").textContent());

  // A tenant and an agent that never reported appear without touching the page. (Other tests share the
  // database and run at the same time, so the counts only ever go up by at least what we added.)
  const count = async (id: string) => Number(await page.getByTestId(id).textContent());
  const agentsBefore = await count("agent-count");
  expect((await api("/v1/tenants", "POST", { name: tenant }, admin)).status).toBe(201);
  await expect.poll(() => count("tenant-count"), { timeout: 15_000 }).toBeGreaterThan(before);
  expect((await api(`/v1/tenants/${tenant}/agents`, "POST", { name: "host-1", groups: ["web"] }, admin)).status).toBe(201);
  await expect.poll(() => count("agent-count"), { timeout: 15_000 }).toBeGreaterThan(agentsBefore);
  // The attention list is the place to look for it: a never-reporting agent is "no recent report".
  await expect(page.getByRole("region", { name: "Needs attention" })).toContainText("no recent report");

  // Recent activity shows the latest audit events (which ones depends on what else is running).
  await expect(page.getByRole("region", { name: "Recent activity" }).getByRole("row")).not.toHaveCount(0);
});

test("a form in progress is not refreshed under the user's hands", async ({ page }) => {
  const tenant = `q${Date.now()}`;
  const admin = await adminToken();
  await api("/v1/tenants", "POST", { name: tenant }, admin);
  await signIn(page);
  await page.goto(`/tenants/${tenant}/policies/new`);
  await expect(page.getByTestId("live-state")).toHaveCount(0); // quiet page: no live indicator, no refresh
  await page.getByTestId("policy-input").fill("draft: in progress");
  await api(`/v1/tenants/${tenant}/agents`, "POST", { name: "x1" }, admin);
  await page.waitForTimeout(2500);
  await expect(page.getByTestId("policy-input")).toHaveValue("draft: in progress");
});

test("the live stream needs a session and says nothing about content", async ({ request }) => {
  expect((await request.get("/api/stream")).status()).toBe(401);
});
