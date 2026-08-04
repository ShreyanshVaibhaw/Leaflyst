import { getTenantId } from "@/lib/tenant";
import { attachmentFilename } from "@/lib/download";

export async function GET() {
  const tenantId = await getTenantId();
  if (!tenantId) return Response.json({ detail: "Tenant not selected" }, { status: 401 });
  const url = new URL("/v1/evidence/tenant", process.env.ABX_API_URL ?? "http://localhost:8000");
  url.searchParams.set("tenant_id", tenantId);
  const upstream = await fetch(url, {
    headers: { "X-ABX-Admin-Key": process.env.ABX_ADMIN_KEY ?? "dev-admin-key" },
    cache: "no-store",
  });
  if (!upstream.ok) {
    return Response.json({ detail: await upstream.text() }, { status: upstream.status });
  }
  return new Response(upstream.body, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "Content-Disposition": attachmentFilename("tenant-evidence.ndjson"),
      "Cache-Control": "no-store",
    },
  });
}
