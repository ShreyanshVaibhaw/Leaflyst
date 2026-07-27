"use server";

import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { adminApiPost } from "@/lib/api";

type DemoResult = {
  tenant_id: string;
  session_id: string;
  credential_id: string;
  finding_id: string;
  scanner_warning: string;
  destructive_attempt: string;
  share_path: string;
  expires_at: string;
};

const visitorCookie = "abx_demo_visitor";

async function visitorReference(): Promise<string> {
  const store = await cookies();
  let visitor = store.get(visitorCookie)?.value;
  if (!visitor || !/^[A-Za-z0-9_-]{43}$/.test(visitor)) {
    visitor = randomBytes(32).toString("base64url");
    store.set(visitorCookie, visitor, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/demo",
      maxAge: 60 * 60 * 24,
    });
  }
  return createHash("sha256").update(visitor).digest("hex");
}

export async function runPocketOSDemo() {
  let result: DemoResult;
  try {
    result = await adminApiPost<DemoResult>("/v1/demo/public/run", {
      visitor_ref: await visitorReference(),
    });
  } catch {
    redirect("/demo?error=unavailable");
  }
  redirect(`/demo?share=${encodeURIComponent(result.share_path)}`);
}
