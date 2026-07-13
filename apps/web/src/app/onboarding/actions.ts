"use server";

import { adminApiPost } from "@/lib/api";
import { currentUserId } from "@/lib/auth";
import { setTenantId } from "@/lib/tenant";

export type OnboardingState = {
  status: "idle" | "success" | "error";
  message?: string;
  ingestToken?: string;
  scanToken?: string;
};

type BootstrapResult = { tenant_id: string; ingest_token: string | null; scan_token: string | null; created: boolean };

export async function bootstrapTenant(
  _previous: OnboardingState,
  formData: FormData,
): Promise<OnboardingState> {
  const tenantName = String(formData.get("tenant_name") ?? "").trim();
  if (!tenantName) return { status: "error", message: "Workspace name is required." };
  const userId = await currentUserId();
  if (!userId) return { status: "error", message: "Sign in before creating a workspace." };
  try {
    const result = await adminApiPost<BootstrapResult>("/v1/onboarding/bootstrap", {
      user_ref: userId,
      tenant_name: tenantName,
    });
    await setTenantId(result.tenant_id, userId);
    return {
      status: "success",
      message: result.created ? "Workspace created. Copy the token now; it will not be shown again." : "Workspace restored on this device.",
      ingestToken: result.ingest_token ?? undefined,
      scanToken: result.scan_token ?? undefined,
    };
  } catch (error) {
    return { status: "error", message: error instanceof Error ? error.message : "Workspace setup failed." };
  }
}
