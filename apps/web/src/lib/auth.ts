import { auth } from "@clerk/nextjs/server";

function runtimeEnvironment(name: string): string {
  // Bracket lookup keeps runtime configuration dynamic in the standalone image.
  return process.env[name] ?? "";
}

export const clerkPublishableKey = runtimeEnvironment(
  "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
);
export const clerkSecretKey = runtimeEnvironment("CLERK_SECRET_KEY");
export const productionAuthRequired = runtimeEnvironment("ABX_ENV") === "production";
export const clerkEnabled = Boolean(clerkPublishableKey && clerkSecretKey);

/**
 * The Clerk frontend API host this instance talks to, decoded from the
 * publishable key, which carries it as base64 with a trailing "$".
 *
 * The content policy needs the exact host. A wildcard for clerk.accounts.dev
 * would cover development instances and quietly fail in production, where a
 * live instance answers on the customer's own domain instead.
 */
export const clerkFrontendApi = (() => {
  if (!clerkPublishableKey) return "";
  const encoded = clerkPublishableKey.replace(/^pk_(test|live)_/, "");
  try {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    return decoded.endsWith("$") ? decoded.slice(0, -1) : "";
  } catch {
    return "";
  }
})();

export async function currentUserId(): Promise<string | null> {
  if (clerkEnabled) return (await auth()).userId;
  if (productionAuthRequired) {
    throw new Error("Clerk authentication is required in production");
  }
  return "local-development-user";
}
