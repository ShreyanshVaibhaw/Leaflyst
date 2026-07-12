"use server";

import { redirect } from "next/navigation";
import { auth } from "@clerk/nextjs/server";
import { adminApiPost, apiPost } from "@/lib/api";
import { clerkEnabled } from "@/lib/auth";
import { setTenantId } from "@/lib/tenant";

type DemoResult = {
  tenant_id: string;
  session_id: string;
  credential_id: string;
  finding_id: string;
  scanner_warning: string;
  destructive_attempt: string;
};

export async function runPocketOSDemo() {
  const result = await apiPost<DemoResult>("/v1/demo/run", {});
  const userId = clerkEnabled ? (await auth()).userId : "local-development-user";
  if (!userId) throw new Error("Sign in before running the demo");
  await setTenantId(result.tenant_id, userId);
  const params = new URLSearchParams({
    session: result.session_id,
    credential: result.credential_id,
    finding: result.finding_id,
  });
  redirect(`/demo?${params.toString()}`);
}

export async function restoreWorkspace() {
  const userId = clerkEnabled ? (await auth()).userId : "local-development-user";
  if (!userId) throw new Error("Sign in before restoring the workspace");
  const result = await adminApiPost<{ tenant_id: string }>("/v1/onboarding/bootstrap", {
    user_ref: userId,
    tenant_name: "Workspace",
  });
  await setTenantId(result.tenant_id, userId);
  redirect("/");
}
