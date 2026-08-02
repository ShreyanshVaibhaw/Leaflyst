import { NextRequest, NextResponse } from "next/server";

import { clerkEnabled, clerkFrontendApi } from "@/lib/auth";

/**
 * Per-request Content Security Policy (SEC-B06).
 *
 * This application renders recorded agent input and output: tool arguments,
 * provider resource names, model responses. All of it is attacker-controlled by
 * design, and React escaping is the first line rather than the only one. The
 * policy therefore allows no inline script at all except the one carrying this
 * request's nonce, which is what makes injected markup inert even if something
 * upstream of React ever emits it raw.
 *
 * The nonce goes on the request as well as the response because that is how
 * Next.js learns to stamp its own bootstrap and hydration scripts with it. Set
 * it only on the response and the policy blocks the framework instead of the
 * attacker.
 */
export function securityResponse(request: NextRequest, existing?: NextResponse): NextResponse {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const development = process.env.NODE_ENV === "development";
  const httpsRequired = process.env.ABX_REQUIRE_HTTPS === "true";

  // Clerk serves its script and talks to its API on the instance's own host, and
  // uses Cloudflare Turnstile for bot detection. Named only when Clerk is on, so
  // a deployment without it does not carry allowances it never uses.
  const clerkScript = clerkEnabled
    ? [clerkFrontendApi ? `https://${clerkFrontendApi}` : "", "https://challenges.cloudflare.com"]
    : [];
  const clerkConnect = clerkEnabled && clerkFrontendApi ? [`https://${clerkFrontendApi}`] : [];
  const clerkImages = clerkEnabled ? ["https://img.clerk.com"] : [];
  const clerkFrames = clerkEnabled ? ["https://challenges.cloudflare.com"] : [];

  const directives = [
    "default-src 'self'",
    // 'unsafe-eval' is React's development-only error reconstruction. Production
    // never gets it.
    `script-src 'self' 'nonce-${nonce}'${development ? " 'unsafe-eval'" : ""} ${clerkScript.join(" ")}`,
    // Inline styles are allowed and inline scripts are not, because a style
    // cannot execute. Keeping a nonce out of this directive is deliberate: a
    // nonce here would make the browser ignore 'unsafe-inline' and break the
    // framework's injected styles.
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: ${clerkImages.join(" ")}`,
    "font-src 'self' data:",
    `connect-src 'self' ${clerkConnect.join(" ")}`,
    "worker-src 'self' blob:",
    `frame-src ${clerkFrames.length ? clerkFrames.join(" ") : "'none'"}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(httpsRequired ? ["upgrade-insecure-requests"] : []),
  ];
  const policy = directives.join("; ").replace(/\s{2,}/g, " ").trim();

  const response =
    existing ??
    NextResponse.next({
      request: { headers: withNonce(request, nonce, policy) },
    });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

function withNonce(request: NextRequest, nonce: string, policy: string): Headers {
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", policy);
  return headers;
}
