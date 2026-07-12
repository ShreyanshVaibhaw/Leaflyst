import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";
import { auth } from "@clerk/nextjs/server";
import { cookies } from "next/headers";
import { clerkEnabled } from "@/lib/auth";

const cookieName = "abx_tenant";

function signature(payload: string) {
  const configured = process.env.ABX_TENANT_COOKIE_SECRET;
  if (process.env.NODE_ENV === "production" && (!configured || configured.length < 32)) {
    throw new Error("ABX_TENANT_COOKIE_SECRET must be at least 32 characters in production");
  }
  const secret = configured ?? process.env.ABX_ADMIN_KEY ?? "dev-tenant-cookie-secret";
  return createHmac("sha256", secret).update(payload).digest("hex");
}

async function membershipAllowed(userRef: string, tenantId: string): Promise<boolean> {
  const url = new URL("/v1/onboarding/authorize", process.env.ABX_API_URL ?? "http://localhost:8000");
  url.searchParams.set("user_ref", userRef);
  url.searchParams.set("tenant_id", tenantId);
  try {
    const response = await fetch(url, {
      headers: { "X-ABX-Admin-Key": process.env.ABX_ADMIN_KEY ?? "dev-admin-key" },
      cache: "no-store",
    });
    if (!response.ok) return false;
    return Boolean(((await response.json()) as { authorized?: boolean }).authorized);
  } catch {
    return false;
  }
}

export async function getTenantId(): Promise<string> {
  const value = (await cookies()).get(cookieName)?.value;
  if (value) {
    const separator = value.lastIndexOf(".");
    if (separator > 0) {
      const payload = value.slice(0, separator);
      const provided = Buffer.from(value.slice(separator + 1), "hex");
      const expected = Buffer.from(signature(payload), "hex");
      if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
        try {
          const parsed = JSON.parse(Buffer.from(payload, "base64url").toString()) as { tenantId?: string; userRef?: string };
          const currentUser = clerkEnabled ? (await auth()).userId : "local-development-user";
          if (parsed.tenantId && parsed.userRef === currentUser) {
            if (!clerkEnabled || await membershipAllowed(currentUser, parsed.tenantId)) {
              return parsed.tenantId;
            }
          }
        } catch {
          // Ignore malformed or legacy cookies and fall through to onboarding.
        }
      }
    }
  }
  return clerkEnabled ? "" : (process.env.ABX_TENANT_ID ?? "");
}

export async function setTenantId(tenantId: string, userRef: string): Promise<void> {
  const payload = Buffer.from(JSON.stringify({ tenantId, userRef })).toString("base64url");
  (await cookies()).set(cookieName, `${payload}.${signature(payload)}`, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
}
