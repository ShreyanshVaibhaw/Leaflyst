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

export async function currentUserId(): Promise<string | null> {
  if (clerkEnabled) return (await auth()).userId;
  if (productionAuthRequired) {
    throw new Error("Clerk authentication is required in production");
  }
  return "local-development-user";
}
