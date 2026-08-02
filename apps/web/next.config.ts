import type { NextConfig } from "next";

// Headers that never vary per request. The Content Security Policy is not here:
// it carries a per-request nonce and is set in proxy.ts. HSTS is emitted only
// where HTTPS is actually required, because pinning a browser to a scheme the
// deployment cannot serve is an outage, not a control.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },
  ...(process.env.ABX_REQUIRE_HTTPS === "true"
    ? [
        {
          key: "Strict-Transport-Security",
          value: "max-age=31536000; includeSubDomains",
        },
      ]
    : []),
];

const nextConfig: NextConfig = {
  output: "standalone",
  // Naming the framework and its version is a free hint about which advisories
  // to try first.
  poweredByHeader: false,
  outputFileTracingIncludes: {
    "/*": ["./node_modules/playwright/**/*", "./node_modules/playwright-core/**/*"],
  },
  turbopack: { root: __dirname },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
