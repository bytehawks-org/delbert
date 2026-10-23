import { createHmac } from "node:crypto";
import { expect, test } from "@playwright/test";

// Needs to reach the Core's API directly to prepare a user (set CORE_URL, and NODE_EXTRA_CA_CERTS for its CA).
const CORE = process.env.CORE_URL;
const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password" };

function base32(data: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of data) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** RFC 6238, SHA-1, 6 digits, 30 s. `step` shifts the window (a code is accepted once). */
function totp(secret: string, step = 0): string {
  const counter = Math.floor(Date.now() / 30000) + step;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", base32(secret)).update(buf).digest();
  const o = h[19]! & 0x0f;
  const n = ((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!;
  return String(n % 1_000_000).padStart(6, "0");
}

async function api(path: string, method: string, body?: unknown, token?: string) {
  const res = await fetch(`${CORE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as Record<string, any> };
}

test.skip(!CORE, "CORE_URL is not set");

test("a user with a second factor signs in with a TOTP code", async ({ page }) => {
  const name = `mfa-${Date.now()}`;
  const password = "a-long-enough-password";
  const admin = (await api("/v1/auth/login", "POST", ADMIN)).json.token as string;
  expect((await api("/v1/users", "POST", { username: name, password, assignments: [{ role: "viewer" }] }, admin)).status).toBe(201);
  const user = (await api("/v1/auth/login", "POST", { username: name, password })).json.token as string;
  const enrol = await api("/v1/me/mfa/enroll", "POST", undefined, user);
  const secret = enrol.json.secret as string;
  expect((await api("/v1/me/mfa/confirm", "POST", { code: totp(secret) }, user)).status).toBe(200);

  await page.goto("/login");
  await page.getByLabel(/username/i).fill(name);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: /second factor/i })).toBeVisible();

  await page.getByLabel(/^code$/i).fill("000000");
  await page.getByRole("button", { name: /verify/i }).click();
  await expect(page.locator("main [role=alert]")).toContainText(/invalid code/i);

  // The confirmation used the current 30-second step; the next one is accepted.
  await page.getByLabel(/^code$/i).fill(totp(secret, 1));
  await page.getByRole("button", { name: /verify/i }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("signed-in-as")).toContainText(name);
});
