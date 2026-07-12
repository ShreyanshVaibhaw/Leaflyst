import { getTenantId } from "@/lib/tenant";

const contentTypes: Record<string, string> = { csv: "text/csv", json: "application/json", md: "text/markdown" };

export async function GET(_request: Request, { params }: { params: Promise<{ format: string }> }) {
  const { format } = await params;
  const tenantId = await getTenantId();
  if (!(format in contentTypes) || !tenantId) return new Response("Not found", { status: 404 });
  const apiUrl = process.env.ABX_API_URL ?? "http://localhost:8000";
  const url = new URL(`/v1/dashboard/findings.${format}`, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { headers: { "X-ABX-Admin-Key": process.env.ABX_ADMIN_KEY ?? "dev-admin-key" }, cache: "no-store" });
  if (!response.ok) return new Response("Export unavailable", { status: response.status });
  return new Response(await response.text(), { headers: { "Content-Type": contentTypes[format], "Content-Disposition": `attachment; filename="credential-findings.${format}"` } });
}
