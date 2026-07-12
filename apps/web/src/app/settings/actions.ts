"use server";

import { revalidatePath } from "next/cache";
import { apiPost, apiPut } from "@/lib/api";

export type TokenState = { status: "idle" | "success" | "error"; token?: string; message?: string };

export async function updateTenantSettings(formData: FormData) {
  await apiPut("/v1/settings", {
    tenant_name: String(formData.get("tenant_name") ?? ""),
    retention_days: Number(formData.get("retention_days")),
    capture_payloads: formData.get("capture_payloads") === "on",
  });
  revalidatePath("/settings");
}

export async function createScopedToken(
  _previous: TokenState,
  formData: FormData,
): Promise<TokenState> {
  try {
    const result = await apiPost<{ token: string; kind: string }>("/v1/settings/tokens", {
      kind: String(formData.get("kind")),
      label: String(formData.get("label") ?? ""),
    });
    revalidatePath("/settings");
    return {
      status: "success", token: result.token,
      message: `${result.kind === "recording" ? "Recording" : "Local scanner"} token created. Copy it now; it will not be shown again.`,
    };
  } catch (error) {
    return { status: "error", message: error instanceof Error ? error.message : "Token creation failed" };
  }
}

export async function revokeScopedToken(kind: string, tokenId: string) {
  await apiPost(`/v1/settings/tokens/${kind}/${tokenId}/revoke`, {});
  revalidatePath("/settings");
}
