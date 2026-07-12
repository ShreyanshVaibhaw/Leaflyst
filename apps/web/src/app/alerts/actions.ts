"use server";
import { revalidatePath } from "next/cache";
import { apiPost, apiPut } from "@/lib/api";

export async function acknowledgeAlert(alertId: string) {
  await apiPost(`/v1/alerts/${alertId}/acknowledge`, {});
  revalidatePath("/alerts");
}

export async function configureChannel(form: FormData) {
  const kind = String(form.get("kind") ?? "");
  const target = String(form.get("target") ?? "");
  await apiPut("/v1/alerts/channels", { kind, target, enabled: true });
  revalidatePath("/alerts");
}
