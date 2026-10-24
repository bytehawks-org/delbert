import { expect, test } from "@playwright/test";


// M4: visual regression of the screens whose content never depends on data. Baselines live in
// e2e/visual.spec.ts-snapshots and are made in the Playwright container (docs/TESTING.md);
// update them with `npx playwright test e2e/visual.spec.ts --update-snapshots` after a deliberate change.
for (const scheme of ["light", "dark"] as const) {
  for (const locale of ["en", "it"]) {
    test(`login page, ${scheme}, ${locale}`, async ({ page, context }) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await context.addCookies([{ name: "NEXT_LOCALE", value: locale, url: process.env.WEB_URL ?? "http://localhost:3000" }]);
      await page.goto("/login");
      await expect(page.getByRole("button", { name: /sign in|accedi/i })).toBeVisible();
      await expect(page).toHaveScreenshot(`login-${scheme}-${locale}.png`, { maxDiffPixelRatio: 0.002, fullPage: true });
    });
  }
}

test("not found page", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.goto("/this-page-does-not-exist");
  await expect(page).toHaveScreenshot("not-found-light.png", { maxDiffPixelRatio: 0.002, fullPage: true });
});
