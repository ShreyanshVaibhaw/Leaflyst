"use server";

import { redirect } from "next/navigation";
import { apiPost } from "@/lib/api";

export async function connectGcp(formData: FormData) {
  const projectId = String(formData.get("project_id") ?? "").trim();
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) {
    redirect("/integrations?gcp=invalid");
  }
  try {
    await apiPost("/v1/integrations/gcp/connect", { project_id: projectId });
  } catch {
    redirect("/integrations?gcp=unavailable");
  }
  redirect(`/integrations?gcp=queued&project=${encodeURIComponent(projectId)}`);
}
