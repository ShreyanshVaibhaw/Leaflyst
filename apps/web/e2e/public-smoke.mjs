import assert from "node:assert/strict";
import { chromium } from "playwright";

const baseURL = process.env.E2E_BASE_URL ?? "http://127.0.0.1:13000";

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));

  try {
    let response = await page.goto(`${baseURL}/security`);
    assert.equal(response?.status(), 200);
    await page.getByRole("heading", { name: "Security and responsible disclosure" }).waitFor();
    assert.equal(await page.locator('a[href="mailto:security@leaflyst.dev"]').count(), 1);

    response = await page.goto(`${baseURL}/share/not-a-token`);
    assert.equal(response?.status(), 200);
    await page.getByText("Dashboard data is unavailable").waitFor();

    response = await page.goto(`${baseURL}/demo`);
    assert.equal(response?.status(), 200);
    await page.getByRole("heading", { name: "PocketOS incident demo" }).waitFor();
    await page.getByRole("button", { name: "Run isolated demo" }).click();
    await page.waitForURL((url) => url.pathname === "/demo" && Boolean(url.searchParams.get("share")));

    const replay = page.getByRole("link", { name: "Open read-only replay" });
    const sharePath = await replay.getAttribute("href");
    assert.match(sharePath ?? "", /^\/share\/abx_share_[A-Za-z0-9_-]+$/);
    await replay.click();
    await page.getByText("Read-only incident replay").waitFor();
    await page.getByText("Redacted payload").click();
    await page.getByText("Sandbox intercepted DROP DATABASE prod_orders; no command was executed.").waitFor();
    assert.equal(await page.locator("main form, main button").count(), 0);
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
