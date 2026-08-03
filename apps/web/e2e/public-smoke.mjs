import assert from "node:assert/strict";
import { chromium } from "playwright";

const baseURL = process.env.E2E_BASE_URL ?? "http://127.0.0.1:13000";

const REQUIRED_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "cross-origin-opener-policy": "same-origin",
};

/**
 * A nonce policy fails silently in the worst way: the page renders from the
 * server, looks correct, and never hydrates because the browser dropped every
 * inline script. Any page served from a cache carries a build-time body that
 * cannot match the nonce sent with the response, so this asserts the two agree.
 */
function assertSecurityHeaders(response, path) {
  const headers = response.headers();
  for (const [name, value] of Object.entries(REQUIRED_HEADERS)) {
    assert.equal(headers[name], value, `${path} is missing ${name}`);
  }
  assert.equal(headers["x-powered-by"], undefined, `${path} still advertises its framework`);
  const csp = headers["content-security-policy"] ?? "";
  assert.match(csp, /frame-ancestors 'none'/, `${path} has no frame-ancestors`);
  assert.match(csp, /object-src 'none'/, `${path} has no object-src`);
  assert.doesNotMatch(csp, /'unsafe-inline'[^;]*;?\s*(?=[^;]*script-src)/, `${path} allows inline script`);
  const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
  assert.ok(nonce, `${path} sent no script nonce`);
  return nonce;
}

async function assertHydrated(page, nonce, path) {
  const applied = await page.evaluate(() =>
    [...document.scripts].filter((script) => !script.src).map((script) => script.nonce),
  );
  assert.ok(
    applied.length === 0 || applied.includes(nonce),
    `${path} serves inline scripts the policy will block`,
  );
}

async function main() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  const violations = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.text().includes("Content Security Policy")) violations.push(message.text());
  });

  try {
    let response = await page.goto(`${baseURL}/security`);
    assert.equal(response?.status(), 200);
    await assertHydrated(page, assertSecurityHeaders(response, "/security"), "/security");
    await page.getByRole("heading", { name: "Security and responsible disclosure" }).waitFor();
    assert.equal(await page.locator('a[href="mailto:security@leaflyst.dev"]').count(), 1);

    response = await page.goto(`${baseURL}/share/not-a-token`);
    assert.equal(response?.status(), 200);
    await page.getByText("Dashboard data is unavailable").waitFor();

    response = await page.goto(`${baseURL}/demo`);
    assert.equal(response?.status(), 200);
    await assertHydrated(page, assertSecurityHeaders(response, "/demo"), "/demo");
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
    assert.deepEqual(violations, [], "the content policy blocked something the app needs");
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
