"use server";
import { revalidatePath } from "next/cache";
import { apiPost } from "@/lib/api";

export async function revokeCredential(credentialId: string, form: FormData) {
  await apiPost(`/v1/revocation/${credentialId}`, {
    confirmation: String(form.get("confirmation") ?? ""),
    action: String(form.get("action") ?? ""),
  });
  revalidatePath(`/credentials/${credentialId}`);
}
