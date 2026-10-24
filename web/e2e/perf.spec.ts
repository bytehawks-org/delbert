import { expect, test } from "@playwright/test";
import { CORE, signIn } from "./helpers";

// M4: performance budget. A first visit to a screen must stay small: JavaScript bytes as they cross the
// network (compressed; the browser cache is off) and no request outside this site (no CDN, fonts, analytics).
test.skip(!CORE, "CORE_URL is not set");

/** Per screen, in bytes on the wire. Raise it deliberately, with a reason, never to make a test pass. */
const BUDGET_JS_BYTES = Number(process.env.WEB_JS_BUDGET ?? 200_000);
const routes = ["/login", "/", "/tenants", "/agents", "/audit", "/roles", "/users", "/profile"];

test("each screen loads within the JavaScript budget and only from its own origin", async ({ page }) => {
  const client = await page.context().newCDPSession(page);
  await client.send("Network.enable");
  await client.send("Network.setCacheDisabled", { cacheDisabled: true });
  const scripts = new Map<string, string>(); // request id -> url
  let wire = 0;
  const foreign: string[] = [];
  let origin = "";
  client.on("Network.responseReceived", (e) => {
    if (origin && !e.response.url.startsWith(origin)) foreign.push(e.response.url);
    if (e.type === "Script") scripts.set(e.requestId, e.response.url);
  });
  client.on("Network.loadingFinished", (e) => {
    if (scripts.has(e.requestId)) wire += e.encodedDataLength;
  });

  const measure = async (route: string) => {
    wire = 0;
    scripts.clear();
    await page.goto(route, { waitUntil: "networkidle" });
    return wire;
  };

  await page.goto("/login");
  origin = new URL(page.url()).origin;
  const report: string[] = [];
  const over: string[] = [];
  for (const route of routes) {
    if (route !== "/login" && page.url().includes("/login")) await signIn(page);
    const bytes = await measure(route);
    report.push(`${route}: ${(bytes / 1024).toFixed(0)} KiB`);
    if (bytes > BUDGET_JS_BYTES) over.push(`${route} loads ${bytes} bytes of JavaScript (budget ${BUDGET_JS_BYTES})`);
    expect(bytes, `${route} must load some JavaScript (the measurement works)`).toBeGreaterThan(10_000);
  }
  console.log(report.join("\n"));
  expect(over).toEqual([]);
  expect(foreign, "requests to other origins").toEqual([]);
});
