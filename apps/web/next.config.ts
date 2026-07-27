import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingIncludes: {
    "/*": ["./node_modules/playwright/**/*", "./node_modules/playwright-core/**/*"],
  },
  turbopack: { root: __dirname },
};

export default nextConfig;
