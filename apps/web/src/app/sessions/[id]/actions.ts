"use server";
import { redirect } from "next/navigation";
import { apiPost } from "@/lib/api";

export async function createSessionShare(sessionId: string) {
  const share = await apiPost<{ share_path: string }>(`/v1/replay/sessions/${encodeURIComponent(sessionId)}/share`, { expires_in_hours: 72 });
  redirect(share.share_path);
}
