import { tenantId } from "@/lib/api";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string; format: string }> }) {
  const { id, format } = await params;
  if (!tenantId || !["csv", "json"].includes(format)) return new Response("Not found", { status: 404 });
  const url = new URL(`/v1/replay/sessions/${encodeURIComponent(id)}/blast-radius.${format}`, process.env.ABX_API_URL ?? "http://localhost:8000");
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { headers: { "X-ABX-Admin-Key": process.env.ABX_ADMIN_KEY ?? "dev-admin-key" }, cache: "no-store" });
  if (!response.ok) return new Response("Export unavailable", { status: response.status });
  const type = format === "csv" ? "text/csv" : "application/json";
  return new Response(await response.text(), { headers: { "Content-Type": type, "Content-Disposition": `attachment; filename="session-${id}-blast-radius.${format}"` } });
}
